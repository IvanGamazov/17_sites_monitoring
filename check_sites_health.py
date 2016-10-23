import requests
import os
import whois
import datetime
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("file", nargs='?', help="Путь до файла с URL'ми для проверки'")
args = parser.parse_args()


def find_domain(url_string):
    url_parts = url_string.split('//')
    try:
        url_parts.remove('https:')
    except ValueError:
        try:
            url_parts.remove('http:')
        except ValueError:
            pass
    domain_parts = url_parts[0].split('/')
    domain_part = domain_parts[0]
    if 'www.' in domain_part:
        domain = domain_part[4:]
    else:
        domain = domain_part
    return domain


def load_urls4check(file_path):
    urls = []
    if os.path.exists(file_path):
        with open(file_path) as urllist:
            for url in urllist:
                url.split()
                urls.append(url[:-1])
    else:
        urls = None
    return urls


def get_server_stat_code(url):
    try:
        stat_code = requests.get(url).status_code
    except requests.exceptions.ConnectionError:
        stat_code = None
    return stat_code



def get_server_status(url):
    if 'http://' or 'https://' not in url:
        status = get_server_stat_code('http://'+url)
        if status is None:
            status = get_server_stat_code('https://' + url)
    else:
        status = get_server_stat_code(+ url)
    return status


def get_full_info(urls):
    url_list = []
    for url in urls:
        domain = find_domain(url)
        url_list.append({
            'domain': url,
            'status': get_server_status(url),
            'exp_date': get_domain_expiration_date(domain)
               })
    return url_list


def expires_in_one_month(expire_date):
    month = datetime.timedelta(days=30)
    if type(expire_date) is not str:
        try:
            expiration = expire_date.pop(0).date()
        except AttributeError:
            expiration = expire_date.date()
        return expiration - month < datetime.datetime.now().date()
    else:
        return None


def get_results(url_list):
    urls_fail = list(filter(lambda url: url['status'] != 200 or url['exp_date'] is None, url_list))
    urls_warning = list(filter(lambda url: url['status'] == 200 and expires_in_one_month(url['exp_date']), url_list))
    urls_ok = list(filter(lambda url: url['status'] == 200 and  not expires_in_one_month(url['exp_date']), url_list))
    return urls_fail, urls_warning, urls_ok


def get_domain_expiration_date(domain_name):
    domain_info = whois.whois(domain_name)
    expiration_date = domain_info.expiration_date
    return expiration_date


if __name__ == '__main__':
    if not args.file:
        urlsfile = input('Путь до файла с URL-ами -->')
    else:
        urlsfile = args.file
    check_list = load_urls4check(urlsfile)
    if check_list is not None:
        if len(check_list):
            urls_info = get_full_info(check_list)
            fail_list, warn_list, ok_list = get_results(urls_info)
            print('URL не прошедшие проверку:')
            for fail in fail_list:
                print(fail['domain'], fail['status'], fail['exp_date'])
            print('URL, регистрация которых истекает в течение месяца:')
            for warning in warn_list:
                print(warning['domain'], warning['exp_date'])
            print('URL прошли проверку:')
            for ok in ok_list:
                print(ok['domain'], 'OK')
        else:
            print('Файл не содержит ссылок')
    else:
        print('Файл со ссылками не найден')

