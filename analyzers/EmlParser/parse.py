#!/usr/bin/env python3
# encoding: utf-8
import datetime
import os
import eml_parser
from cortexutils.analyzer import Analyzer
import magic
import binascii
import base64
import imgkit
from PIL import Image
from io import BytesIO
from bs4 import BeautifulSoup

# TODO: Optional: add a flavor: with image (the other one gives all http links found in the message, can be run as a second analysis. Manage PAP/TLP, use at your own risk)
 

class EmlParserAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        #filename of the observable
        self.filename = self.getParam('attachment.name', 'noname.ext')
        self.filepath = self.getParam('file', None, 'File is missing')

        # Gather ConfigurationItems
        self.wkhtmltoimage = {
            'enable': self.get_param('config.email_visualisation', False),
            'path': self.get_param(
                'config.wkhtmltoimage_path', '/usr/bin/wkhtmltoimage'),
            'width_size': self.get_param('config.width_size', 1024)
        }
    
    def run(self):
        if self.data_type == 'file':
            try:
                parsingResult = parseEml(
                    self.filepath, self.job_directory, self.wkhtmltoimage)
                self.report(parsingResult)
            except Exception as e:
                # self.unexpectedError(e)
                print(e)

        else:
            self.notSupported()

    def summary(self, raw):
        level = "info"
        namespace = "EmlParser"
        predicate_attachments = "Attachments"
        predicate_urls = "Urls"
        value_urls = "0"

        value_attachments = len(raw['attachments']) if 'attachments' in raw else "0"
        if 'url' in raw.get('iocs'):
            value_urls = len(raw.get('iocs').get('url'))

        taxonomies = [
            self.build_taxonomy(
                level, namespace, predicate_attachments, value_attachments
            ),
            self.build_taxonomy(level, namespace, predicate_urls, value_urls),
        ]

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        urls = raw.get('iocs').get('url')
        ip = raw.get('iocs').get('ip')
        domains = raw.get('iocs').get('domain')

        ## Extract email addresses
        mail_addresses = raw.get('iocs').get('email')
        hashes = raw.get('iocs').get('hash')

        if urls:
            artifacts.extend(self.build_artifact('url',str(u)) for u in urls)
        if ip:
            artifacts.extend(self.build_artifact('ip',str(i)) for i in ip)
        if mail_addresses:
            artifacts.extend(self.build_artifact('mail',str(e)) for e in mail_addresses)
        if domains: 
            artifacts.extend(self.build_artifact('domain',str(e)) for e in domains)
        if hashes:
            for h in hashes:
                artifacts.extend(
                    (
                        self.build_artifact('hash', str(h.get('hash'))),
                        self.build_artifact('filename', str(h['filename'])),
                    )
                )

                filepath = os.path.join(self.job_directory, 'output', h.get('filename'))
                artifacts.append(self.build_artifact('file', filepath))

        # if 'text_html' in raw.get('body'):
        #     urls.extend(raw.get('body').get('text_html').get('uri')  
        return artifacts


def parseEml(filepath, job_directory, wkhtmltoimage):

    ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
    with open(filepath, 'rb') as f:
        raw_email = f.read()

    decoded_email = ep.decode_email_bytes(raw_email)

    ##
    ## Results
    ##
    result = dict()
    iocs = dict()
    iocs['ip'] = list()
    iocs['domain'] = list()
    iocs['url'] = list()
    iocs['email'] = list()
    iocs['hash'] = list()
    iocs['files'] = list()

    ##
    ## Extract raw email
    ## 
    result['raw_email'] = raw_email.decode('utf-8')
    ##
    ## Extract SMTP envelope
    ##
    headers = dict()
    headers['return-path'] = decoded_email.get('header').get('header').get('return-path', '')
    headers['delivered-to'] = decoded_email.get(
        'header').get('header').get('delivered-to', '')
    headers['x-delivered-to'] = decoded_email.get(
        'header').get('header').get('x-delivered-to', '')

    ##
    ## Extract Headers 
    ## 
    headers['from'] = decoded_email.get('header').get('header').get('from', [])
    headers['to'] = decoded_email.get('header').get('header').get('to', [])
    headers['cc'] = decoded_email.get('header').get('header').get('cc', [])
    headers['bcc'] = decoded_email.get('header').get('header').get('bcc', [])
    headers['reply-to'] = decoded_email.get('header').get('header').get('reply-to', [])
    headers['subject'] = decoded_email.get('header').get('header').get('subject', '')
    headers['date'] = decoded_email.get('header').get('header').get('date', '')[0]
    headers['received'] = decoded_email.get('header').get('received')
    # Make dates ready for json
    for h in headers['received']: 
        if isinstance(h.get('date'), datetime.datetime):
            d = h.get('date').isoformat()
            h['date'] = d
    result['headers'] = headers

    ##
    ## Extract body text/plain and text/html
    ## 
    body = dict()
    if 'body' in decoded_email:
        body['text_plain'] = list()
        body['text_html'] = list()
        for b in decoded_email.get('body'):
            ## text/plain
            if b.get('content_type') == "text/plain":
                body['text_plain'].append(b)                
                b['beautified_text'] = BeautifulSoup(
                        b.get('content'), 'html.parser').prettify()
                iocs['url'].extend(ep.get_uri_ondata(b.get('content')))
            
            ## text/html
            elif b.get('content_type') == "text/html":
                iocs['url'].extend(ep.get_uri_ondata(b.get('content')))
               
               ## Generate rendering image if option is enabled
                if wkhtmltoimage.get('enable'):

                    img_file = convert_png(b.get('content'), 0, wkhtmltoimage.get('path'), "/tmp")
                    b['rendered_html'] = "data:{};base64,{}".format(
                        "image/png",
                        base64_image(img_file.get('img_path'),
                                     wkhtmltoimage.get('width_size')
                                     )
                    )
                    b['beautified_html'] = BeautifulSoup(
                        b.get('content'), 'html.parser').prettify()
                
                body['text_html'].append(b)
    result['body'] = body

    ##
    ## Extract Attachments
    ## 
    result['attachments'] = list()
    if 'attachment' in decoded_email.keys():
        for a in decoded_email.get('attachment'):
            a['mime'] = magic.from_buffer(binascii.a2b_base64(a.get('raw')))
            if isinstance(a.get('raw'), bytes):
                filepath = os.path.join(job_directory, 'output', a.get('filename', ''))
                with open(filepath, 'wb') as f:
                    f.write(base64.b64decode(a['raw']))
                f.close()
                a['raw'] = a.get('raw').decode('ascii')
            result['attachments'].append(a)
            iocs['hash'].extend([{
                'hash': a.get('hash').get('sha256'),
                'filename': a.get('filename')
            }])
    
    ##
    ## Extract IOCs
    ## 
    iocs['ip'].extend(decoded_email.get('header').get('received_ip', []))
    iocs['domain'].extend(decoded_email.get('header').get('received_domain', []))
    ### Email
    for field in ['cc', 
                  'bcc',
                  'delivered_to',
                  'received_foremail',
                  ]:
        iocs['email'].extend(decoded_email.get('header').get(field, []))
    iocs['email'].append(decoded_email.get('header').get('from', ''))

    result['iocs'] = iocs

    return result


def convert_png(content: str, i, wkhtmltoimage_path:str, output_path: str):

    config = imgkit.config(
        wkhtmltoimage=wkhtmltoimage_path
    )
    options = {'no-images': '',
               'encoding': 'UTF-8',
               'disable-javascript': '',
               'load-media-error-handling': 'ignore',
                'load-error-handling':'ignore'
               }
    imgkit.from_string(content, 
                       "{}/{}.png".format(output_path, i),
                       options=options,
                       config=config
                       )
    return {'index': i, 'img_path': "{}/{}.png".format(output_path, i)}


def base64_image(img_path, width):
    """
    :param content: raw image
    :type content: raw
    :param width: size of the return image
    :type width: int
    :return: base64 encoded image
    :rtype: string
    """
    try:
        image = Image.open(img_path)
        ft = image.format
        wpercent = (width / float(image.size[0]))
        if image.size[0] > width:
            hsize = int(float(image.size[1]) * float(wpercent))
            image = image.resize((width, hsize), Image.ANTIALIAS)
        ImgByteArr = BytesIO()
        image.save(ImgByteArr, format=ft)
        ImgByteArr = ImgByteArr.getvalue()
        with BytesIO(ImgByteArr) as bytes:
            encoded = base64.b64encode(bytes.read())
            base64_image = encoded.decode()
        return base64_image

    except Exception as e:
        return "No image"

if __name__ == '__main__':
    EmlParserAnalyzer().run()
