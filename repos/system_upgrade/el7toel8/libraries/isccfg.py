#!/usr/bin/env python
#
# Simplified parsing of bind configuration, with include support and nested sections.

import re
import os.path
import string
import copy

class ConfigParseError(Exception):
    """ Generic error when parsing config file """

    def __init__(self, message, error=None):
        super(ConfigParseError, self).__init__(message)
        self.error = error
    pass

class ConfigFile(object):
    """ Representation of single configuration file and its contents """
    def __init__(self, path):
        """
        Load config file contents from path

        :param path: Path to file
        """
        self.path = path
        self.load(path)
        self.status = None

    def __str__(self):
        return self.buffer

    def __repr__(self):
        return 'ConfigFile {0} ({1})'.format(
                self.path, self.buffer)

    def load(self, path):
        with open(path, 'r') as f:
            self.buffer = self.original = f.read()
            f.close()

    def is_modified(self):
        return self.original == self.buff

    def root_section(self):
        return ConfigSection(self, None, 0, len(self.buffer))

class ConfigSection(object):
    """ Representation of section or key inside single configuration file """

    TYPE_BARE = 1
    TYPE_QSTRING = 2
    TYPE_BLOCK = 3

    def __init__(self, config, name=None, start=None, end=None):
        """
        :param config: config file inside which is this section
        :type config: ConfigFile
        """
        self.config = config
        self.name = name
        self.start = start
        self.end = end

    def __repr__(self):
        text = self.config.buffer[self.start:self.end+1]
        path = self.config.path
        return 'ConfigSection({path}:{start}-{end}: "{text}")'.format(
            path=path, start=self.start, end=self.end,
            text=text
        )

    def copy(self):
        return ConfigSection(self.config, self.name, self.start, self.end)


    def type(self):
        if self.config.buffer.startswith('{', self.start):
            return self.TYPE_BLOCK
        elif self.config.buffer.startswith('"', self.start):
            return self.TYPE_QSTRING
        return self.TYPE_BARE

    def value(self):
        return self.config.buffer[self.start:self.end+1]

    def invalue(self):
        """
        Return just inside value of blocks and quoted strings
        """
        t = self.type()
        if t != self.TYPE_BARE:
            return self.config.buffer[self.start+1:self.end]
        return self.value()
    pass

class ConfigVariableSection(ConfigSection):
    """
    Representation for key and value with variable parameters

    Intended for view and zone.
    """
    def __init__(self, sectionlist, name, zone_class=None, parent=None):
        """
        Creates variable block for zone or view

        :param sectionlist: list of ConfigSection, obtained from IscConfigParser.find_values()
        """
        last = next(reversed(sectionlist))
        first = sectionlist[0]
        super(ConfigVariableSection, self).__init__(
            first.config, name, start=first.start, end=last.end
        )
        self.values = sectionlist
        # For optional dns class, like IN or CH
        self.zone_class = zone_class
        self.parent = parent

    def key(self):
        if self.zone_class is None:
            return self.name
        return self.zone_class + '_' + self.name

    def firstblock(self):
        """
        Return first block section in this tool
        """
        for section in self.values:
            if section.type() == ConfigSection.TYPE_BLOCK:
                return section
        return None


# Main parser class
class IscConfigParser(object):
    """ Parser file with support of included files.

    Reads ISC BIND configuration file and tries to skip commented blocks, nested sections and similar stuff.
    Imitates what isccfg does in native code, but without any use of native code.
    """

    CONFIG_FILE = "/etc/named.conf"
    FILES_TO_CHECK = []

    CHAR_DELIM = ";" # Must be single character
    CHAR_CLOSING = CHAR_DELIM + "})]"
    CHAR_CLOSING_WHITESPACE = CHAR_CLOSING + string.whitespace
    CHAR_KEYWORD = string.ascii_letters + string.digits + '-_'
    CHAR_STR_OPEN = '"'

    def __init__(self, config=None):
        """ Construct parser

            :param config: path to file or already loaded ConfigFile instance
            Initialize contents from path to real config or already loaded ConfigFile class.
        """
        if isinstance(config, ConfigFile):
            self.FILES_TO_CHECK = [config]
            self.load_included_files()
        elif config is not None:
            self.load_config(config)

    ###########################################################
    ### function for parsing of config files
    ###########################################################
    def is_comment_start(self, istr, index=0):
        if istr[index] == "#" or (
                index+1 < len(istr) and istr[index:index+2] in ["//", "/*"]):
            return True
        return False

    def find_end_of_comment(self, istr, index=0):
        """
        Returns index where the comment ends.

        :param istr: input string
        :param index: begin search from the index; from the start by default

        Support usual comments till the end of line (//, #) and block comment
        like (/* comment */). In case that index is outside of the string or end
        of the comment is not found, return -1.

        In case of block comment, returned index is position of slash after star.
        """
        length = len(istr)

        if index >= length or index < 0:
            return -1

        if istr[index] == "#" or istr[index:].startswith("//"):
            return istr.find("\n", index)

        if index+2 < length and istr[index:index+2] == "/*":
            res = istr.find("*/", index+2)
            if res != -1:
                return res + 1

        return -1

    def is_opening_char(self, c):
        return c in "\"'{(["

    def remove_comments(self, istr, space_replace=False):
        """
        Removes all comments from the given string.

        :param istr: input string
        :param space_replace When true, replace comments with spaces. Skip them by default.
        :return: istr without comments
        """

        ostr = ""

        length = len(istr)
        index = 0

        while index < length:
            if self.is_comment_start(istr, index):
                index = self.find_end_of_comment(istr, index)
                if index == -1:
                    index = length
                if space_replace:
                    ostr = ostr.ljust(index)
                if index < length and istr[index] == "\n":
                    ostr += "\n"
            elif istr[index] in self.CHAR_STR_OPEN:
                end_str = self.find_closing_char(istr, index)
                if end_str == -1:
                    ostr += istr[index:]
                    break
                ostr += istr[index:end_str+1]
                index = end_str
            else:
                ostr += istr[index]
            index += 1

        return ostr

    def replace_comments(self, istr):
        """
        Replaces all comments by spaces in the given string.

        :param istr: input string
        :returns: string of the same length with comments replaced
        """
        return self.remove_comments(istr, True)

    def remove_comments_config(self, cfg, space_replace=False):
        config_nocomment = copy.copy(cfg)
        config_nocomment.buffer = self.remove_comments(config_nocomment.buffer, space_replace)
        return config_nocomment

    def find_next_token(self, istr, index=0, end_index=-1, end_report=False):
        """
        Return index of another interesting token or -1 when there is not next.

        :param istr: input string
        :param index: begin search from the index; from the start by default
        :param end_index: stop searching at the end_index or end of the string

        In case that initial index contains already some token, skip to another.
        But when searching starts on whitespace or beginning of the comment,
        choose the first one.

        The function would be confusing in case of brackets, but content between
        brackets is not evaulated as new tokens.
        E.g.:

        "find { me };"      : 5
        " me"               : 1
        "find /* me */ me " : 13
        "/* me */ me"       : 9
        "me;"               : 2
        "{ me }; me"        : 6
        "{ me }  me"        : 8
        "me }  me"          : 3
        "}} me"             : 1
        "me"                : -1
        "{ me } "           : -1
        """
        length = len(istr)
        if length < end_index or end_index < 0:
            end_index = length

        if index >= end_index or index < 0:
            return -1

        #skip to the end of the current token
        if istr[index] == '\\':
            index += 2
        elif self.is_opening_char(istr[index]):
            index = self.find_closing_char(istr, index, end_index)
            if index != -1:
                index += 1
        elif self.is_comment_start(istr, index):
            index = self.find_end_of_comment(istr, index)
            if index != -1:
                index += 1
        elif istr[index] not in self.CHAR_CLOSING_WHITESPACE:
            # so we have to skip to the end of the current token
            index += 1
            while index < end_index:
                if (istr[index] in self.CHAR_CLOSING_WHITESPACE
                        or self.is_comment_start(istr, index)
                        or self.is_opening_char(istr[index])):
                    break
                index += 1
        elif end_report and istr[index] in self.CHAR_DELIM:
            # Found end of statement. Report delimiter
            return index
        elif istr[index] in self.CHAR_CLOSING:
            index += 1

        # find next token (can be already under the current index)
        while index >= 0 and index < end_index:
            if istr[index] == '\\':
                index += 2
                continue
            elif self.is_comment_start(istr, index):
                index = self.find_end_of_comment(istr, index)
                if index == -1:
                    break
            elif self.is_opening_char(istr[index]) or istr[index] not in string.whitespace:
                return index
            index += 1
        return -1


    def find_closing_char(self, istr, index=0, end_index=-1):
        """
        Returns index of equivalent closing character.

        :param istr: input string

        It's similar to the "find" method that returns index of the first character
        of the searched character or -1. But in this function the corresponding
        closing character is looked up, ignoring characters inside strings
        and comments. E.g. for
            "(hello (world) /* ) */ ), he would say"
        index of the third ")" is returned.
        """
        important_chars = { #TODO: should be that rather global var?
            "{" : "}",
            "(" : ")",
            "[" : "]",
            "\"" : "\"",
            self.CHAR_DELIM : None,
            }
        length = len(istr)
        if end_index >= 0 and end_index < length:
            length = end_index

        if length < 2:
            return -1

        if index >= length or index < 0:
            return -1

        closing_char = important_chars.get(istr[index], self.CHAR_DELIM)
        if closing_char is None:
            return -1

        isString = istr[index] in "\""
        index += 1
        curr_c = ""
        while index < length:
            curr_c = istr[index]
            if curr_c == '//':
                index += 2
            elif self.is_comment_start(istr, index) and not isString:
                index = self.find_end_of_comment(istr, index)
                if index == -1:
                    return -1
            elif not isString and self.is_opening_char(curr_c):
                deep_close = self.find_closing_char(istr[index:])
                if deep_close == -1:
                    break
                index += deep_close
            elif curr_c == closing_char:
                if curr_c == self.CHAR_DELIM:
                    index -= 1
                return index
            index += 1

        return -1

    def find_key(self, istr, key, index=0, end_index=-1, only_first=True):
        """
        Return index of the key or -1.

        :param istr: input string; it could be whole file or content of a section
        :param key: name of the searched key in the current scope
        :param index: start searching from the index
        :param end_index: stop searching at the end_index or end of the string

        Funtion is not recursive. Searched key has to be in the current scope.
        Attention:

        In case that input string contains data outside of section by mistake,
        the closing character is ignored and the key outside of scope could be
        found. Example of such wrong input could be:
              key1 "val"
              key2 { key-ignored "val-ignored" };
            };
            controls { ... };
        In this case, the key "controls" is outside of original scope. But for this
        cases you can set end_index to value, where searching should end. In case
        you set end_index higher then length of the string, end_index will be
        automatically corrected to the end of the input string.
        """
        length = len(istr)
        keylen = len(key)

        if length < end_index or end_index < 0:
            end_index = length

        if index >= end_index or index < 0:
            return -1

        while index != -1:
            #remains = istr[index:]
            if istr.startswith(key, index):
                if index+keylen < end_index and istr[index+keylen] not in self.CHAR_KEYWORD:
                    # key has been found
                    return index

            while not only_first and index != -1 and istr[index] != self.CHAR_DELIM:
                index = self.find_next_token(istr, index)
            index = self.find_next_token(istr, index)

        return -1

    def find_next_key(self, cfg, index=0, end_index=-1, end_report=False):
        """ Modernized variant of find_key
            :type cfg: ConfigFile
            :param index: Where to start search

            Searches for first place of bare keyword, without quotes or block.
        """
        istr = cfg.buffer
        length = len(istr)

        if length < end_index or end_index < 0:
            end_index = length

        if index > end_index or index < 0:
            raise IndexError("Invalid cfg index")

        while index != -1:
            keystart = index
            while istr[index] in self.CHAR_KEYWORD and index < end_index:
                index += 1

            if index <= end_index and keystart < index and istr[index] not in self.CHAR_KEYWORD:
                # key has been found
                return ConfigSection(cfg, istr[keystart:index], keystart, index-1)
            elif istr[index] in self.CHAR_DELIM:
                return ConfigSection(cfg, istr[index], index, index)

            index = self.find_next_token(istr, index, end_index, end_report)

        return None

    def find_next_val(self, cfg, key=None, index=0, end_index=-1, end_report=False):
        """ Find following token.

            :param cfg: input token
            :type cfg: ConfigFile
            :returns: ConfigSection object or None
            :rtype: ConfigSection
        """
        start = self.find_next_token(cfg.buffer, index, end_index, end_report)
        if start < 0:
            return None
        if end_index < 0:
            end_index = len(cfg.buffer)
        #remains = cfg.buffer[start:end_index]
        if start >= 0 and not self.is_opening_char(cfg.buffer[start]):
            return self.find_next_key(cfg, start, end_index, end_report)

        end = self.find_closing_char(cfg.buffer, start, end_index)
        if end == -1 or (end > end_index and end_index > 0):
            return None
        return ConfigSection(cfg, key, start, end)

    def find_val(self, cfg, key, index=0, end_index=-1):
        """ Find value of keyword specified by key

            :param cfg: ConfigFile
            :param key: name of searched key (str)
            :param index: start of search in cfg (int)
            :param end_index: end of search in cfg (int)
            :returns: ConfigSection object or None
            :rtype: ConfigSection
        """
        if not isinstance(cfg, ConfigFile):
            raise TypeError("cfg must be ConfigFile parameter")

        if end_index < 0:
            end_index = len(cfg.buffer)
        key_start = self.find_key(cfg.buffer, key, index, end_index)
        if key_start < 0 or key_start+len(key) >= end_index:
            return None
        return self.find_next_val(cfg, key, key_start+len(key), end_index)

    def find_val_section(self, section, key):
        """ Find value of keyword in section
            :param section: section object returned from find_val

            Section is object found by previous find_val call.
        """
        if not isinstance(section, ConfigSection):
            raise TypeError("section must be ConfigSection")
        return self.find_val(section.config, key, section.start+1, section.end)

    def find_values(self, section, key):
        """ Find key in section and list variable parameters

            :param key: Name to statement to find
            :returns: List of all found values in form of ConfigSection. First is key itself.

            Returns all sections of keyname. They can be mix of "quoted strings", {nested blocks}
            or just bare keywords. First key is section of key itself, final section includes ';'.
            Makes it possible to comment out whole section including terminal character.
        """

        if isinstance(section, ConfigFile):
            cfg = section
            index = 0
            end_index = len(cfg.buffer)
        elif isinstance(section, ConfigSection):
            cfg = section.config
            index = section.start+1
            end_index = section.end
            if end_index > index:
                end_index -= 1
        else:
            raise TypeError('Unexpected type')

        key_start = self.find_key(cfg.buffer, key, index, end_index)
        key_end = key_start+len(key)-1
        if key_start < 0 or key_end >= end_index:
            return None

        # First value is always just keyword
        v = ConfigSection(cfg, key, key_start, key_end)
        values = []
        while isinstance(v, ConfigSection):
            values.append(v)
            if v.value() == self.CHAR_DELIM:
                break
            v = self.find_next_val(cfg, key, v.end+1, section.end, end_report=True)
        return values

    def find(self, key_string, cfg=None, delimiter='.'):
        """
        Helper searching for values under requested sections

        Search for statement under some sections. It is inspired by xpath style paths,
        but searches section in bind configuration.

        :param key_string: keywords delimited by dots. For example options.dnssec-lookaside
        :ptype key_string: str
        :param cfg: Search only in given config file
        :ptype cfg: ConfigFile
        :returns: list of ConfigVariableSection
        """
        keys = key_string.split(delimiter)
        if cfg is not None:
            return self._find_values_simple(cfg.root_section(), keys)

        items = []
        for cfgs in self.FILES_TO_CHECK:
            items.extend(self._find_values_simple(cfgs.root_section(), keys))
        return items

    def _variable_section(self, vl, parent=None):
        """ Create ConfigVariableSection with a name and optionally class

            Intended for view and zone in bind.
            :returns: ConfigVariableSection
        """
        variable = None
        if vl is not None and len(vl) >= 2:
            vname = vl[1].invalue()
            vclass = None
            vblock = vl[2]
            if vblock.type() != ConfigSection.TYPE_BLOCK and len(vl) > 3:
                vclass = vblock.value()
                vblock = vl[3]
            variable = ConfigVariableSection(vl, vname, vclass, parent)
        return variable

    def _find_values_simple(self, section, keys):
        found_values = []
        sect = section.copy()

        while sect is not None:
            vl = self.find_values(sect, keys[0])
            if vl is None:
                break
            if len(keys) <= 1:
                variable = self._variable_section(vl, section)
                found_values.append(variable)
                sect.start = variable.end+1
            else:
                for v in vl:
                    if v.type() == ConfigSection.TYPE_BLOCK:
                        vl2 = self._find_values_simple(v, keys[1:])
                        if vl2 is not None:
                            found_values.extend(vl2)
                sect.start = vl[-1].end+1

        return found_values

    #######################################################
    ### CONFIGURATION fixes PART - END
    #######################################################

    def is_file_loaded(self, path=""):
        """
        Checks if the file with a given 'path' is already loaded in FILES_TO_CHECK.
        """
        for f in self.FILES_TO_CHECK:
            if f.path == path:
                return True
        return False

    def new_config(self, path, parent=None):
        config = ConfigFile(path)
        self.FILES_TO_CHECK.append(config)
        return config

    def load_included_files(self):
        """
        Finds the configuration files that are included in some configuration
        file, reads it, closes and adds into the FILES_TO_CHECK list.
        """
        #TODO: use parser instead of regexp
        pattern = re.compile(r'include\s*"(.+?)"\s*;')
        # find includes in all files
        for ch_file in self.FILES_TO_CHECK:
            nocomments = self.remove_comments(ch_file.buffer)
            includes = re.findall(pattern, nocomments)
            for include in includes:
                # don't include already loaded files -> prevent loops
                if self.is_file_loaded(include):
                    continue
                try:
                    self.new_config(include)
                except IOError as e:
                    raise(ConfigParseError(
                            "Cannot open the configuration file: \"{path}\" "
                            "included by \"{parent_path}\"".format(
                                parent_path=ch_file.path, path=include
                            ), e)
                         )


    def load_main_config(self):
        """
        Loads main CONFIG_FILE.
        """
        try:
            self.new_config(self.CONFIG_FILE)
        except IOError as e:
            raise(ConfigParseError(
                "Cannot open the configuration file: \"{path}\"".format(path=self.CONFIG_FILE)), e)

    def load_config(self, path=None):
        """
        Loads main config file with all included files.
        """
        if path != None:
            self.CONFIG_FILE = path
        self.load_main_config()
        self.load_included_files()
    pass

class BindParser(IscConfigParser):
    """
    Bind specific specialization IscConfigParser.

    Provides some helpers for classes only used in BIND, not generic isccfg format.
    """

    def find_options(self):
        """ Helper to find options section in current files

            :rtype ConfigSection:
            There has to be only one options in all included files.
        """
        for cfg in self.FILES_TO_CHECK:
            v = self.find_val(cfg, "options")
            if v is not None:
                return v
        return None

    def find_views_file(self, cfg):
        """
        Helper searching all views in single file

        :ptype cfg: ConfigFile
        :returns: triple (viewsection, class, list[sections])
        """
        views = {}

        root = cfg.root_section()
        while root is not None:
            vl = self.find_values(root, "view")
            variable = self._variable_section(vl)
            if variable is not None:
                views[variable.key()] = variable
                # Skip current view
                root.start = variable.end+1
            else:
                # no more usable views
                root = None

        return views

    def find_views(self):
        """ Helper to find view section in current files

            :rtype ConfigSection:
            There has to be only one view with that name in all included files.
        """
        views = {}

        for cfg in self.FILES_TO_CHECK:
            v = self.find_views_file(cfg)
            views.update(v)
        return views

    pass
