# https://suhas.org/function-call-ast-python/

'''
Get all function calls from a python file

The MIT License (MIT)
Copyright (c) 2016 Suhas S G <jargnar@gmail.com>
'''
import ast
from collections import deque
import astor


class FuncCallVisitor(ast.NodeVisitor):
    def __init__(self):
        self._name = deque()

    @property
    def name(self):
        return '.'.join(self._name)

    @name.deleter
    def name(self):
        self._name.clear()

    def visit_Name(self, node):
        self._name.appendleft(node.id)

    def visit_Attribute(self, node):
        try:
            self._name.appendleft(node.attr)
            self._name.appendleft(node.value.id)
        except AttributeError:
            self.generic_visit(node)


def get_func_calls(tree):
    func_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callvisitor = FuncCallVisitor()
            callvisitor.visit(node.func)
            func_calls.append((callvisitor.name, node.lineno, node.col_offset, node.args))

    return func_calls


class FunctionTransformer(ast.NodeTransformer):
    def __init__(self, detected_vulnerabilities):
        self.detected_vulnerabilities = detected_vulnerabilities

    def visit_Call(self, node):
        self.generic_visit(node)
        for vulnerability in self.detected_vulnerabilities:
            if vulnerability.line == node.lineno and vulnerability.column == node.col_offset:
                if vulnerability.update:
                    replacement = ast.parse(vulnerability.update).body[0].value

                    if isinstance(ast.parse(vulnerability.update).body[0], ast.Call):
                        args = ast.parse(vulnerability.update).body[0].value.args

                        for i, arg in enumerate(args):
                            if isinstance(arg, ast.Name) and arg.id.startswith('___'):
                                arg_index = int(arg.id[3:])
                                replacement.args[i] = node.args[arg_index]

                    ast.fix_missing_locations(replacement)
                    return replacement

        return node


def replace_func_calls(tree, detected_vulnerabilities):
    return astor.to_source(FunctionTransformer(detected_vulnerabilities).visit(tree))
