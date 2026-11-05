"""Shared navigation renderer for the homepage and vendored project themes."""
from html import escape


def site_links(config, projects, root, overrides=None):
    """Resolve common routes and verified project destinations once per build.

    ``root`` is a relative homepage prefix or an absolute homepage URL ending
    in '/'. Project sites pass the absolute homepage URL. Overrides are for a
    project's own canonical destination and its repository link, not for a new
    navigation definition.
    """
    links = {key: root + path for key, path in config['paths'].items()}
    links['discover'] = links['home'] + '#discover'
    links['github'] = config['github']
    for key, project in projects.items():
        links[key] = project['publication_url'] if project['published'] else project['repository']
    links.update(overrides or {})
    return links


def navigation_links(items, links, active='', github_icon='', footer=False):
    """Render the same configured links, labels and active state on every site."""
    result = []
    for item in items:
        key = item['key']
        url = links[key]
        external = url.startswith('https://github.com/')
        label = item['label'] + (' ↗' if external else '')
        attributes = f' href="{escape(url, quote=True)}"'
        if key == active:
            attributes += ' aria-current="page"'
        if key == 'github':
            attributes += f' class="github-{ "footer-link" if footer else "link"}"'
        elif external:
            attributes += f' title="{escape(item["label"], quote=True)} project repository on GitHub"'
        result.append(f'<a{attributes}>{github_icon if key == "github" else ""}{escape(label)}</a>')
    return ''.join(result)
