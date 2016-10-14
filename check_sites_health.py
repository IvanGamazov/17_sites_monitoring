import requests
import os
import whois


def load_urls4check(file_path):
    urls = []
    if os.path.exists(file_path):
        with open(file_path) as urllist:
            for url in urllist:
                url.split()
                urls.append(url[:-1])
    return urls


def get_server_respond(url):
    response = requests.request('GET', 'http://'+url)
    return response.status_code


def get_results(urls):
    for url in urls:
        yield {
            'domain': url,
            'status': get_server_respond(url),
            'exp_date': get_domain_expiration_date(url)
               }


def get_domain_expiration_date(domain_name):
    domain_info = whois.whois(domain_name)
    expiration_date = domain_info.expiration_date
    try:
        exp_date = expiration_date[0].date()
    except:
        exp_date = expiration_date.date()
    return exp_date


if __name__ == '__main__':
    urlsfile = input('Путь до файла с URL-ами -->')
    check_list = load_urls4check(urlsfile)
    urls_info = get_results(check_list)
    for url in urls_info:
        print(url['domain'], url['status'], url['exp_date'])
