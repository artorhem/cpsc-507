from yattag import Doc
from colorama import init, Fore, Back, Style



class Report:
    def __init__(self, detected_vulnerabilities, tests, updates, replace):
        init() # initialize coloring
        self.vulnerabilities = detected_vulnerabilities
        self.tests = tests
        self.updates = updates
        self.replace = replace

    def html_report(self, output_path):
        pass

    def plain_text_report(self):
        vulnerable_functions_print = ''
        tests_print = 'todo'        # todo
        updates_print = 'todo'      # todo

        for vulnerability in self.vulnerabilities:
            vulnerability_entry = vulnerability.file + ':' + str(vulnerability.line) + ':' + str(vulnerability.column) + '\n'
            # todo get source context
            #vulnerability_entry += '\t' + vulnerability.line + ' | ' + '\n'

            if vulnerability.import_location:
                vulnerability_entry += '\t Import: ' + vulnerability.import_location.line + ':' + vulnerability.import_location.column + ':' + vulnerability.import_location.name + '\n'

            vulnerability_entry += '\t Detected vulnerability: ' + Back.RED + vulnerability.name + Style.RESET_ALL + '\n'  
            vulnerability_entry += '\t Vulnerability reason: ' + vulnerability.reason + '\n' 
            vulnerability_entry += '\t Suggested replacements: ' + vulnerability.update + '\n' 

            if self.replace:
                vulnerability_entry += '\t Automatically replaced with: ' + vulnerability.update + '\n\n'

            vulnerable_functions_print += vulnerability_entry + '\n\n'

        report = 'Detected vulerable functions: \n' + vulnerable_functions_print
        report += 'Executed Tests: \n' + tests_print    # todo
        report += 'Updated dependencies: \n' + updates_print    # todo

        return report

    def pull_request_report(self):
        pass
