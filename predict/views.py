from urllib.error import URLError
from django.shortcuts import redirect, render
from django.http import HttpResponse, HttpResponseRedirect
from django.views import generic
from .forms import urlForm, urlReport
from .extract import whoisDomain, predictURL, get_screenshot, validate_url, whoisRegistrar, report, whoisCity, whoisAddress, whoisOrg, whoisName, whoisNS, WhoisExpDate, WhoisCreationDate
from .models import historyModel
from django.shortcuts import get_object_or_404

from django.contrib.auth.decorators import login_required







@login_required(login_url='/login/')
def predict(request):
    if request.method == "POST":
        form = urlForm(request.POST)
        reportForm = urlReport(request.POST)

        if reportForm.is_valid():
            url_report = request.POST.get('url_report')
            url_report = reportForm.cleaned_data["url_report"]

            current_user = request.user
            email = current_user.email
            url_report_send = report(url_report, email)
            # print(url_report_send) 
            # messages.success(request, 'Contact request submitted successfully.')
            return render(request, 'messages.html', {'url_report_send': url_report_send})
            





        if form.is_valid():
            url = form.cleaned_data["url"]
            url_prediction = predictURL(url)
            screenshot = get_screenshot(url)

            whois_domain = whoisDomain(url)
            whois_registrar = whoisRegistrar(url)
            whois_ns = whoisNS(url)
            whois_name = whoisName(url)
            whois_org = whoisOrg(url)
            whois_address = whoisAddress(url)
            whois_city = whoisCity(url)
            whois_exp = WhoisExpDate(url)
            whois_crt = WhoisCreationDate(url)

            new_record = historyModel(url=url,
                                    is_phishing=url_prediction,
                                    screenshot=screenshot,
                                    whois_domain=whois_domain,
                                    whois_registrar=whois_registrar,
                                    whois_ns = whois_ns,
                                    whois_name = whois_name,
                                    whois_org = whois_org,
                                    whois_address = whois_address,
                                    whois_city = whois_city,
                                    whois_exp = whois_exp,
                                    whois_crt = whois_crt,
                                    )
            new_record.save()

            request.user.url_user.add(new_record)
            return HttpResponseRedirect("/%i" %new_record.id)

            
    else:
        form = urlForm()
        reportForm = urlReport()

    return render(request, "home.html", {'form':form, 'reportForm':reportForm})


# def report(request):
#     if request.method == "POST":
#         reportForm = urlReport(request.POST)
#         if reportForm.is_valid():
#             url = request.POST.get('url')
#     else:
#         reportForm = urlReport()

#     return render(request, "report.html", {'reportForm':reportForm})

def history(response):
    print(response)
    return render(response, "history.html", {})


def result(response, id):
    data = historyModel.objects.get(id=id)
    # ls = historyModel.objects.all()
    url =data.url
    is_phishing = data.is_phishing
    # print(is_phishing)
    screenshot = data.screenshot
    whois_domain = data.whois_domain
    whois_registrar = data.whois_registrar
    whois_ns = data.whois_ns
    whois_name = data.whois_name
    whois_org = data.whois_org
    whois_address = data.whois_address
    whois_city = data.whois_city
    whois_exp = data.whois_exp
    whois_crt = data.whois_crt
    # whois_detail = data.whois_detail
    # print(data_2)
    # whois_domain = data_2.whois_domain
    # whois_registrar = data_2.whois_registrar
    if is_phishing == True:
        is_phishing = "Phishing"
    else:
        is_phishing = "Legitimate"
    context = {
            "url":url,
            "is_phishing":is_phishing,
            "screenshot":screenshot,
            "whois_domain":whois_domain,
            "whois_registrar":whois_registrar,
            "whois_ns":whois_ns,
            "whois_name":whois_name,
            "whois_org":whois_org,
            "whois_address":whois_address,
            "whois_city":whois_city,
            "whois_exp":whois_exp,
            "whois_crt":whois_crt,
            }

    return render(response, "result.html", context)


def delete(response, id):
    data = historyModel.objects.get(id=id)
    data.delete()
    return redirect('history')

