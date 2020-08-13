from isccfg import IscConfigParser


class BindParser(IscConfigParser):
    """Bind specific specialization IscConfigParser.

    Provides some helpers for classes only used in BIND, not generic isccfg format.
    """

    def find_options(self):
        """Helper to find options section in current files.

        :rtype ConfigSection:

        There has to be only one options in all included files.
        """
        for cfg in self.FILES_TO_CHECK:
            v = self.find_val(cfg, "options")
            if v is not None:
                return v
        return None

    def find_views_file(self, cfg):
        """Helper searching all views in single file.

        :type cfg: ConfigFile
        :returns: triple (viewsection, class, list[sections])
        """
        views = {}

        root = cfg.root_section()
        while root is not None:
            vl = self.find_values(root, "view")
            if vl is None:
                root = None
                break
            variable = self._variable_section(vl, root)
            if variable is not None:
                views[variable.key()] = variable
                # Skip current view
                root.start = variable.end+1
            else:
                # no more usable views
                root = None

        return views

    def find_views(self):
        """Helper to find view section in current files.

        :rtype ConfigSection:

        There has to be only one view with that name in all included files.
        """

        views = {}

        for cfg in self.FILES_TO_CHECK:
            v = self.find_views_file(cfg)
            views.update(v)
        return views

    pass
