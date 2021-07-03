from flask import url_for
from jinja2.utils import urlize

from flaskr.utils.template_filters import replace_newline

def make_message_format(user, messages):
    message_tag = ''
    for message in messages:
        message_tag += '<div class="col-lg-1 col-md-1 col-sm-2 col-2">'
        if user.picture_path:
            message_tag += f'<img class="user-img-mini" src={url_for("static", filename=user.picture_path)} alt="icon">'
        message_tag += f'''
            <p>{ user.username }</p>
            </div>
            <div class="speech-bubble-dest col-lg-4 col-md-8 col-sm-8 col-9">
        '''
        for splitted_message in replace_newline(message.message):
            message_tag += f'<p>{urlize(splitted_message)}</p>'
        message_tag += '''
            </div>
            <div class="col-lg-7 col-md-3 col-sm-1 col-1"></div>
        '''
    return message_tag