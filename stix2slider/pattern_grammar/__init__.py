'''
Validates a user entered pattern against STIXPattern grammar.
'''

from __future__ import print_function

import six

from antlr4 import CommonTokenStream, InputStream, ParseTreeWalker
from antlr4.error.ErrorListener import ErrorListener
from stix2slider.pattern_grammar.STIXPatternLexer import STIXPatternLexer
from stix2slider.pattern_grammar.STIXPatternParser import STIXPatternParser
from stix2slider.pattern_grammar.STIXPatternVisitor import STIXPatternVisitor


class STIXPatternErrorListener(ErrorListener):
    '''
    Modifies ErrorListener to collect error message and set flag to False when
    invalid pattern is encountered.
    '''
    def __init__(self):
        super(STIXPatternErrorListener, self).__init__()
        self.err_strings = []

    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.err_strings.append("FAIL: Error found at line %d:%d. %s" %
                                (line, column, msg))


def create_pattern_object(pattern):
    '''
    Validates a pattern against the STIX Pattern grammar.  Error messages are
    returned in a list.  The test passed if the returned list is empty.
    '''

    start = ''
    if isinstance(pattern, six.string_types):
        start = pattern[:2]
        pattern = InputStream(pattern)

    if not start:
        start = pattern.readline()[:2]
        pattern.seek(0)

    parseErrListener = STIXPatternErrorListener()

    lexer = STIXPatternLexer(pattern)
    # it always adds a console listener by default... remove it.
    lexer.removeErrorListeners()

    stream = CommonTokenStream(lexer)

    parser = STIXPatternParser(stream)
    parser.buildParseTrees = True
    # it always adds a console listener by default... remove it.
    parser.removeErrorListeners()
    parser.addErrorListener(parseErrListener)

    # To improve error messages, replace "<INVALID>" in the literal
    # names with symbolic names.  This is a hack, but seemed like
    # the simplest workaround.
    for i, lit_name in enumerate(parser.literalNames):
        if lit_name == u"<INVALID>":
            parser.literalNames[i] = parser.symbolicNames[i]

    tree = parser.pattern()
    builder = STIXPatternVisitor()
    return builder.visit(tree)
