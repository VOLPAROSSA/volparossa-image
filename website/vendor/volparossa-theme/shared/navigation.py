"""Shared navigation renderer for the homepage and vendored project themes."""
from html import escape


def add_application_items(config, apps):
    """Prepare the header navigation for a build or a standalone theme export."""
    for item in config['main']:
        if item['key'] == 'applications':
            item['children'] = [
                {'name': app['name'], 'url': app['publication_url'] if app['published'] else '#' + app['id']}
                for app in apps
            ]


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
        link = f'<a{attributes}>{github_icon if key == "github" else ""}{escape(label)}</a>'
        if item.get('children') and not footer:
            entries = []
            for app in item['children']:
                target = app['url']
                if target.startswith('#'):
                    target = url + target
                entries.append(f'<li><a href="{escape(target, quote=True)}">{escape(app["name"])}</a></li>')
            link = (f'<div class="applications-menu">{link}'
                    '<button type="button" class="applications-toggle" aria-label="Application links" '
                    'aria-expanded="false" hidden><span aria-hidden="true"></span></button>'
                    f'<ul class="applications-list" hidden>{"".join(entries)}</ul></div>')
        result.append(link)
    return ''.join(result)
