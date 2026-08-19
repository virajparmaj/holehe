from holehe.core import *
from holehe.localuseragent import *


async def facebook(email, client, out):
    name = "facebook"
    domain = "facebook.com"
    method = "register"
    frequent_rate_limit = True

    # NOTE: this module was contributed as a copy of the Instagram one with the
    # domain swapped. The endpoint below is an Instagram path and does not exist
    # on facebook.com, so it cannot return a true positive. It is kept only so
    # the site keeps a slot in the catalogue; it is disabled by default and needs
    # a real rewrite against a Facebook endpoint before it means anything.
    headers = {
        'User-Agent': random.choice(ua["browsers"]["chrome"]),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Origin': 'https://www.facebook.com',
        'DNT': '1',
        'Connection': 'keep-alive',
    }

    def report(rate_limit, exists):
        out.append({"name": name, "domain": domain, "method": method,
                    "frequent_rate_limit": frequent_rate_limit,
                    "rateLimit": rate_limit,
                    "exists": exists,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None})

    try:
        response = await client.get(
            "https://www.facebook.com/accounts/emailsignup/", headers=headers)
        token = response.text.split('{"config":{"csrf_token":"')[1].split('"')[0]
    except Exception:
        report(rate_limit=True, exists=False)
        return None

    headers["x-csrftoken"] = token
    data = {
        'email': email,
        'username': ''.join(random.choice(string.ascii_lowercase + string.digits)
                            for _ in range(random.randint(6, 30))),
        'first_name': '',
        'opt_into_one_tap': 'false',
    }

    try:
        check = await client.post(
            "https://www.facebook.com/api/v1/web/accounts/web_create_ajax/attempt/",
            data=data,
            headers=headers)
        check = check.json()
    except Exception:
        report(rate_limit=True, exists=False)
        return None

    if check.get("status") == "fail":
        report(rate_limit=True, exists=False)
    elif 'email' in check.get("errors", {}):
        errors = check["errors"]
        taken = errors["email"][0].get("code") == "email_is_taken"
        if taken or "email_sharing_limit" in str(errors):
            report(rate_limit=False, exists=True)
        else:
            report(rate_limit=True, exists=False)
    else:
        report(rate_limit=False, exists=False)
