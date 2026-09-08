"""Single operation-argument registry for validation and generated JSON Schema.

Only typed operation arguments are listed. UI target selector objects retain the
upstream pywinauto contract. Registry metadata does not grant execution authority.
"""
from __future__ import annotations

BROWSER = {
    'goto': 'url wait_until', 'click': 'selector', 'dblclick': 'selector', 'fill': 'selector text',
    'press': 'selector key', 'check': 'selector', 'uncheck': 'selector', 'select_option': 'selector value label index',
    'hover': 'selector', 'wait_for': 'selector state', 'wait_for_url': 'url wait_until',
    'wait_for_load_state': 'state', 'reload': 'wait_until', 'wait_for_text': 'text',
    'wait_for_function': 'expression arg', 'bring_to_front': '', 'sleep': 'seconds',
    'text': 'selector', 'content': '', 'attribute': 'selector name', 'input_value': 'selector', 'count': 'selector',
    'screenshot': 'path selector full_page', 'evaluate': 'expression arg', 'upload': 'selector files path',
    'download': 'selector save_as', 'click_popup': 'selector wait_until', 'new_page': '', 'pages': '',
    'switch_page_matching': 'match', 'switch_page': 'index', 'close_page': 'allow_borrowed_close',
    'cookies_get': 'urls', 'cookies_add': 'cookies', 'cookies_clear': '', 'storage_state': 'path',
    'pdf': 'path format print_background', 'url': '', 'title': '', 'snapshot': '',
}
UI = {
    'discover_dialog': 'process_id kind title title_contains class_names',
    'file_dialog_path': 'path', 'file_dialog_filename': 'filename automation_ids',
    'file_dialog_accept': 'button_automation_ids', 'file_dialog_cancel': '',
    'explorer_navigate': 'path', 'explorer_select': 'name', 'explorer_open': 'name',
    'explorer_new_folder': 'name', 'explorer_rename': 'name new_name', 'explorer_delete': 'name',
    'explorer_copy': 'name', 'explorer_cut': 'name', 'explorer_paste': '',
    'list_windows': 'limit title_contains class_name', 'cursor_position': '', 'input_desktop': '',
    'active_window': '', 'dump_tree': 'max_depth max_nodes', 'wait_ready': '', 'wait_visible': '',
    'invoke': '', 'set_value': 'text', 'set_text': 'text', 'get_text': '', 'exists': '', 'is_visible': '',
    'is_enabled': '', 'get_rect': '', 'summary': '', 'select': '', 'toggle': '', 'expand': '', 'collapse': '',
    'close': '', 'focus': '', 'set_focus': '', 'maximize': '', 'minimize': '', 'restore': '',
    'move_resize': 'x y width height', 'click': '', 'click_input': 'button coords double wheel_dist pressed',
    'type_keys': 'keys pause with_spaces with_tabs with_newlines', 'move_mouse': 'coords',
    'click_at': 'coords button', 'double_click_at': 'coords button', 'right_click_at': 'coords',
    'scroll': 'coords wheel_dist', 'drag': 'start end button', 'hotkey': 'keys pause',
    'type_text': 'text pause restore_clipboard', 'clipboard_get': '', 'clipboard_set': 'text',
    'sleep': 'seconds', 'capture': 'name', 'capture_desktop': 'name',
}
COMMON = {'op', 'metadata', 'settle_seconds', 'timeout_seconds', 'after_seconds', 'timeout_ms'}
BOOLS = {'full_page','print_background','allow_borrowed_close','double','with_spaces','with_tabs','with_newlines','restore_clipboard'}
STRINGS = {'url','selector','text','key','keys','name','new_name','filename','path','save_as','expression','title','title_contains','class_name','format','kind','state','wait_until','frame','button'}
POINTS = {'coords','start','end'}


def allowed(name: str, browser: bool) -> set[str]:
    registry = BROWSER if browser else UI
    return set(registry[name].split()) | COMMON | ({'frame'} if browser else {'control'})


def check_arguments(operation: dict, browser: bool) -> None:
    name = operation.get('op')
    registry = BROWSER if browser else UI
    if name not in registry:
        raise ValueError('unknown browser/UI operation')
    unknown = set(operation) - allowed(name, browser)
    if unknown:
        raise ValueError('unsupported operation argument(s): ' + ', '.join(sorted(unknown)))
    for key, value in operation.items():
        if key in BOOLS and type(value) is not bool:
            raise ValueError(f'{key} must be boolean')
        if key in STRINGS and not isinstance(value, str):
            raise ValueError(f'{key} must be a string')
    if name in {'fill', 'set_value', 'set_text', 'type_text', 'clipboard_set'} and not isinstance(operation.get('text'), str):
        raise ValueError('text is required, including an explicit empty string when clearing')
    if name == 'upload':
        files = operation.get('files', operation.get('path'))
        if not (isinstance(files, str) and files or isinstance(files, list) and 1 <= len(files) <= 100 and all(isinstance(x,str) and x for x in files)):
            raise ValueError('upload requires a path or bounded file list')
    if name == 'cookies_add' and (not isinstance(operation.get('cookies'), list) or not operation['cookies']):
        raise ValueError('cookies_add requires cookies')
    if 'control' in operation and not isinstance(operation['control'], dict):
        raise ValueError('control must be a selector object')
    if 'button' in operation and operation['button'] not in {'left','right','middle'}:
        raise ValueError('invalid mouse button')
    from .common import bounded_number
    for key, low, high in (('wheel_dist',-1000,1000), ('process_id',1,2**32-1), ('limit',1,1000), ('max_depth',0,12), ('max_nodes',1,2000)):
        if key in operation:
            bounded_number(operation[key],key,low,high,True)


def schema(browser: bool) -> dict:
    registry = BROWSER if browser else UI
    variants = []
    for name in sorted(registry):
        props = {}
        for key in sorted(allowed(name, browser)):
            if key == 'op':
                spec = {'const':name}
            elif key in BOOLS:
                spec = {'type':'boolean'}
            elif key in STRINGS:
                spec = {'type':'string'}
            elif key in POINTS:
                spec = {'type':'array','minItems':2,'maxItems':2,'items':{'type':'integer','minimum':-100000,'maximum':100000}}
            else:
                spec = {}
            props[key] = spec
        required = ['op']
        if name in {'fill','set_value','set_text','type_text','clipboard_set'}:
            required.append('text')
        variants.append({'type':'object','properties':props,'required':required,'additionalProperties':False})
    return {'oneOf':variants}
