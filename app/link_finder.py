from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, parse_qs
import html

UNSUBSCRIBE_KEYWORDS_EN = [
    "unsubscribe", "subscription", "opt-out", "opt out", "manage your subscription", 
    "email preferences", "notification settings", "mailing list", "no longer wish to receive",
    "remove me from this list", "update your preferences"
]

UNSUBSCRIBE_KEYWORDS_DE = [
    "abbestellen", "abmelden", "austragen", "newsletter abbestellen", "vom newsletter abmelden",
    "einstellungen", "benachrichtigungen", "mailingliste", "keine weiteren e-mails", 
    "von dieser liste entfernen", "einstellungen aktualisieren", "kündigen"
]

ALL_KEYWORDS = UNSUBSCRIBE_KEYWORDS_EN + UNSUBSCRIBE_KEYWORDS_DE

def resolve_redirect(url):
    """
    Resolves redirect URLs from common email providers.
    """
    try:
        parsed_url = urlparse(url)
        if 'deref-gmx.net' in parsed_url.netloc or 'deref-web.de' in parsed_url.netloc:
            query_params = parse_qs(parsed_url.query)
            if 'redirectUrl' in query_params:
                return query_params['redirectUrl'][0]
    except Exception:
        # Ignore parsing errors and return original url
        pass
    return url

def find_unsubscribe_links(html_content):
    """
    Finds unsubscribe links in an HTML content.
    Returns a list of dictionaries, each with 'text' and 'href'.
    """
    soup = BeautifulSoup(html_content, 'lxml')
    links = {}

    for a in soup.find_all('a', href=True):
        link_text = a.get_text(strip=True)
        link_href = a['href']

        # Basic filtering
        if not link_href.startswith('http') or 'mailto:' in link_href or 'javascript:void' in link_href:
            continue
        
        # Check if text or href contains keywords
        text_match = any(re.search(r'\b' + re.escape(keyword) + r'\b', link_text, re.IGNORECASE) for keyword in ALL_KEYWORDS)
        href_match = any(re.search(r'\b' + re.escape(keyword) + r'\b', link_href, re.IGNORECASE) for keyword in ALL_KEYWORDS)

        if text_match or href_match:
            # Resolved the URL (lxml already handles basic entity unescaping in attributes)
            resolved_href = resolve_redirect(link_href)
            
            # Use link_text if available, otherwise use the URL itself
            display_text = link_text if link_text else resolved_href
            
            # Use resolved_href as the key to avoid duplicates of the same final link
            links[resolved_href] = {'text': display_text, 'href': resolved_href}

    # Also search for "list-unsubscribe" headers which are sometimes in the HTML body
    list_unsubscribe_nodes = soup.find_all(string=re.compile(r'List-Unsubscribe', re.IGNORECASE))
    for node in list_unsubscribe_nodes:
        # This is a basic implementation. Real List-Unsubscribe headers are in email headers,
        # but sometimes they are mirrored in the HTML for clients that don't read headers.
        # This looks for <mailto:..> and <http://...> patterns after the text.
        
        # The regex looks for an opening bracket/paren, captures the content, and then a closing one.
        # It handles both mailto and http/https links.
        matches = re.findall(r'<(?P<url>(mailto|https?):[^>]+)>', str(node.find_parent()))
        for url_match in matches:
            url = url_match[0]
            if url.startswith('http'):
                resolved_href = resolve_redirect(url)
                links[resolved_href] = {'text': 'List-Unsubscribe', 'href': resolved_href}

    return list(links.values())

