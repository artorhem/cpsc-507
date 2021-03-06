import re
import sys
import time
import os
import json

try:
    import thread
except:
    import _thread as thread

import sublime
import sublime_plugin

Pref = {}
settings_base = {}



def plugin_loaded():

    global settings_base
    global Pref

    settings = sublime.load_settings('Word Highlight.sublime-settings')
    if int(sublime.version()) >= 2174:
        settings_base = sublime.load_settings('Preferences.sublime-settings')
    else:
        settings_base = sublime.load_settings('Base File.sublime-settings')

    class Pref:
        def load(self):
            Pref.color_scope_name = settings.get('color_scope_name', "comment")
            Pref.highlight_delay = settings.get('highlight_delay', 0)
            Pref.case_sensitive = (not bool(settings.get('case_sensitive', True))) * sublime.IGNORECASE
            Pref.draw_outlined = bool(settings.get('draw_outlined', True)) * sublime.DRAW_OUTLINED
            Pref.mark_occurrences_on_gutter = bool(settings.get('mark_occurrences_on_gutter', False))
            Pref.icon_type_on_gutter = settings.get("icon_type_on_gutter", "dot")
            Pref.highlight_when_selection_is_empty = bool(settings.get('highlight_when_selection_is_empty', False))
            Pref.highlight_word_under_cursor_when_selection_is_empty = bool(
                settings.get('highlight_word_under_cursor_when_selection_is_empty', False))
            Pref.highlight_non_word_characters = bool(settings.get('highlight_non_word_characters', False))
            Pref.word_separators = settings_base.get('word_separators')
            Pref.show_status_bar_message = bool(settings.get('show_word_highlight_status_bar_message', True))
            Pref.file_size_limit = int(settings.get('file_size_limit', 4194304))
            Pref.when_file_size_limit_search_this_num_of_characters = int(
                settings.get('when_file_size_limit_search_this_num_of_characters', 20000))
            Pref.timing = time.time()
            Pref.enabled = True
            Pref.prev_selections = None
            Pref.prev_regions = None
            Pref.select_next_word_skiped = 0
            Pref.prev_critical_regions = None
            relative_path = os.path.join(os.path.join(sublime.packages_path(), 'cpsc-507'), 'db')
            json_file = os.path.join(relative_path, 'vulnerabilities.sublime-tooltip')
            data = json.load(open(json_file))

            Pref.vulnerabilities = data


    Pref = Pref()
    Pref.load()

    VulnerabilityHighlightListener().highlight_occurences(sublime.active_window().active_view())

    settings.add_on_change('reload', lambda: Pref.load())
    settings_base.add_on_change('VulnerabilityHighlight-reload', lambda: Pref.load())
    if Pref.highlight_when_selection_is_empty and not 'running_wh_loop' in globals():
        global running_wh_loop
        running_wh_loop = True
        thread.start_new_thread(wh_loop, ())


def wh_loop():
    while True:
        sublime.set_timeout(lambda: VulnerabilityHighlightListener().on_selection_modified(
            sublime.active_window().active_view() if sublime.active_window() else None), 0)
        time.sleep(5)


# Backwards compatibility with Sublime 2.  sublime.version isn't available at module import time in Sublime 3.
if sys.version_info[0] == 2:
    plugin_loaded()


def escape_regex(str):
    # Sublime text chokes when regexes contain \', \<, \>, or \`.
    # Call re.escape to escape everything, and then unescape these four.
    str = re.escape(str)
    for c in "'<>`":
        str = str.replace('\\' + c, c)
    return str


class set_word_highlight_enabled(sublime_plugin.ApplicationCommand):
    def run(self):
        Pref.enabled = not Pref.enabled
        if not Pref.enabled:
            sublime.active_window().active_view().erase_regions("VulnerabilityHighlight")
            sublime.active_window().active_view().erase_regions("VulnerabilityHighlightCritical")
        else:
            VulnerabilityHighlightListener().highlight_occurences(sublime.active_window().active_view())

    def description(self):
        return 'Disable' if Pref.enabled else 'Enable'


class VulnerabilityHighlightClickCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        Pref.select_next_word_skiped = 0
        view = self.view
        if Pref.enabled and not view.settings().get('is_widget'):
            VulnerabilityHighlightListener().highlight_occurences(view)

class ReplaceVulnerabilityCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        view = self.view
        sel = view.sel()
        word_region = view.word(sel[0])
        word = view.substr(word_region)
        for string, metadata in Pref.vulnerabilities.items():
            last_element = string.split('.')[-1]
            if last_element == word:
                if not metadata["update_with"]:
                    break
                update_element = metadata["update_with"].split('.')[-1]
                print(metadata["update_with"].split('.'))
                print(metadata["update_with"].split('.')[-1])
                print('update element', update_element)
                view.replace(edit, word_region, update_element)
                break

class ReplaceSimilarVulnerabilitiesCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        view = self.view
        sel = view.sel()
        word_region = view.word(sel[0])
        word = view.substr(word_region)
        regions = view.find_all(word)
        for string, metadata in Pref.vulnerabilities.items():
            last_element = string.split('.')[-1]
            if last_element == word:
                if not metadata["update_with"]:
                    break
                update_element = metadata["update_with"].split('.')[-1]
                while regions:
                    print(regions)
                    region = regions[0]
                    view.replace(edit, region, update_element)
                    regions = view.find_all(word)

class ReplaceAllVulnerabilitiesCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        view = self.view
        shift = 0
        for string, metadata in Pref.vulnerabilities.items():
            last_element = string.split('.')[-1]
            current_regions = view.find_all(last_element)
            if not metadata["update_with"]:
                continue
            update_element = metadata["update_with"].split('.')[-1]
            while current_regions:
                region = current_regions[0]
                view.replace(edit, region, update_element)
                current_regions = view.find_all(last_element)



class VulnerabilityHighlightListener(sublime_plugin.EventListener):
    def on_activated(self, view):
        Pref.prev_selections = None
        Pref.select_next_word_skiped = 0
        if not view.is_loading():
            Pref.word_separators = view.settings().get('word_separators') or settings_base.get('word_separators')
            if not Pref.enabled:
                view.erase_regions("VulnerabilityHighlight")
                view.erase_regions("VulnerabilityHighlightCritical")

    def on_selection_modified(self, view):
        if view and Pref.enabled and not view.settings().get('is_widget'):
            now = time.time()
            if now - Pref.timing > 0.08:
                Pref.timing = now
                sublime.set_timeout(lambda: self.highlight_occurences(view), 0)
            else:
                Pref.timing = now

    def set_status(self, view, message):
        if Pref.show_status_bar_message:
            view.set_status("VulnerabilityHighlight", message)
    def highlight_occurences(self, view):
        prev_selections = str(list(view.sel()))
        if Pref.prev_selections == prev_selections:
            return
        else:
            Pref.prev_selections = prev_selections

        if view.size() <= Pref.file_size_limit:
            limited_size = False
        else:
            limited_size = True

        print('running', str(time.time()))

        regions = []
        occurrencesMessage = []
        occurrencesCount = 0
        critical_regions = []
        for string, metadata in Pref.vulnerabilities.items():
            last_element = string.split('.')[-1]
            current_regions = view.find_all(last_element)
            if metadata["severity"] == "critical":
                critical_regions.extend(current_regions)
            else:
                regions.extend(current_regions)
        if Pref.prev_regions != regions:
            view.erase_regions("VulnerabilityHighlight")
            if regions:
                view.add_regions('VulnerabilityHighlight', regions, 'warning', '', sublime.DRAW_NO_FILL)
            else:
                view.erase_status("VulnerabilityHighlight")
        Pref.prev_regions = regions
        if Pref.prev_critical_regions != critical_regions:
            view.erase_regions("VulnerabilityHighlightCritical")
            if critical_regions:
                view.add_regions('VulnerabilityHighlightCritical', critical_regions, 'invalid', '', sublime.DRAW_NO_FILL)
                    # view.add_regions("VulnerabilityHighlight", regions, Pref.color_scope_name, Pref.icon_type_on_gutter if Pref.mark_occurrences_on_gutter else "", sublime.DRAW_SOLID_UNDERLINE)
            else:
                view.erase_status("VulnerabilityHighlightCritical")
        Pref.prev_critical_regions = critical_regions
