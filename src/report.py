from yattag import Doc
from colorama import init, Fore, Back, Style


class Report:
    def __init__(self,
                 detected_vulnerable_functions,
                 detected_vulnerable_imports,
                 tests, updates, replace):
        """
        Creates a new report instance.
        :param detected_vulnerabilities: vulnerabilities that have been detected in the analysis
        :param tests: test results
        :param updates: information about outdated and updated dependencies
        :param replace: whether automatic replacement is activated
        """
        init()  # initialize coloring
        self.detected_vulnerable_functions = detected_vulnerable_functions
        self.detected_vulnerable_imports = detected_vulnerable_imports
        self.tests = tests
        self.updates = updates
        self.replace = replace

    def html_report(self, output_path):
        """
        Write the report as HTML into the provided file.
        :param output_path: location of the generated HTML file containing the report
        """
        doc, tag, text, line = Doc().ttl()
        line('h1', 'Analysis Report')
        line('h2', 'Detected vulnerable functions')

        # todo: style file

        with tag('div', id='vulnerabilities'):
            for vulnerability in self.detected_vulnerable_functions:
                with tag('div', klass='entry'):
                    with tag('div', klass='file_path'):
                        text(vulnerability.file)

                    if vulnerability.import_location:
                        with tag('div', klass='import'):
                            text(
                                'Import: ' + vulnerability.import_location.line + ':' + vulnerability.import_location.column + ':' + vulnerability.import_location.name)

                    with tag('div', klass='vulnerability'):
                        text('Detected vulnerability: ' + vulnerability.name)

                    with tag('div', klass='reason'):
                        text('Vulnerability reason: ' + vulnerability.reason)

                    with tag('div', klass='replacement'):
                        text('Suggested replacement: ' + vulnerability.update)

                    if self.replace:
                        with tag('div', klass='replacement'):
                            text('Automatically replaced with: ' + vulnerability.update)

        result = doc.getvalue()
        file = open(output_path, 'w')
        file.write(result)
        file.close()
        print 'Wrote HTML report: ' + output_path

    def plain_text_report(self):
        """
        Creates a report in plaintext with color highlighting.
        :return: report in formated plain text
        """
        vulnerable_functions_print = ''
        tests_print = 'todo'  # todo
        updates_print = 'todo'  # todo

        for vulnerability in self.detected_vulnerable_functions:
            vulnerability_entry = vulnerability.file + ':' + str(vulnerability.line) + ':' + str(
                vulnerability.column) + '\n'
            # todo get source context
            # vulnerability_entry += '\t' + vulnerability.line + ' | ' + '\n'

            if vulnerability.import_location:
                vulnerability_entry += '\t Import: ' + vulnerability.import_location.line + ':' + vulnerability.import_location.column + ':' + vulnerability.import_location.name + '\n'

            vulnerability_entry += '\t Detected vulnerability: ' + Back.RED + vulnerability.name + Style.RESET_ALL + '\n'
            vulnerability_entry += '\t Vulnerability reason: ' + vulnerability.reason + '\n'
            vulnerability_entry += '\t Suggested replacements: ' + vulnerability.update + '\n'

            if self.replace:
                vulnerability_entry += '\t Automatically replaced with: ' + vulnerability.update + '\n\n'

            vulnerable_functions_print += vulnerability_entry + '\n\n'

        report = 'Detected vulerable functions: \n' + vulnerable_functions_print
        report += 'Executed Tests: \n' + tests_print  # todo
        report += 'Updated dependencies: \n' + updates_print  # todo

        return report

    def pull_request_report(self):
        """
        Create a report used for pull-requests.
        :return: Markdown report
        """
        report = '''We found potential vulnerability risks in your dependencies and used functions.
                    Some vulnerabilities have been replaced by safe alternatives.'''
        report += '# Vulnerable Functions \n'

        vulnerable_functions_print = ''

        for vulnerability in self.detected_vulnerable_functions:
            vulnerability_entry = '*' + vulnerability.file + ':' + str(vulnerability.line) + ':' + str(
                vulnerability.column) + ':* '

            vulnerability_entry += vulnerability.name + '\n'
            vulnerability_entry += '* Reason: ' + vulnerability.reason + '\n'
            vulnerability_entry += '* Replacement: ' + vulnerability.update + '\n'

            vulnerable_functions_print += vulnerability_entry + '\n\n'

        report += vulnerable_functions_print

        report += '# Vulnerable Dependencies \n'
        report += '[todo]'

        report += '# Test Report \n'
        report += '[todo]'

        report += '''--- \n
        This tool was developed as part of a Software Engineering course. 
        If you have feedback then please reply to this pull-request. Thank you!
        '''

        return report

