from django import forms
from .models import historyModel, reportModel
# creating a form
class urlForm(forms.Form):
	url = forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Enter a URL: https://example.xyz/xyz?=xyz", "id": "text-fb83", "name": "url_check", "class": "u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-1"}), label='')


	class Meta:
		model = historyModel
		fields = "url"


class urlReport(forms.Form):
	url_report = forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Enter a URL", "id": "text-fb83", "name": "text", "class": "u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-1"}), label='')

	class Meta:
		model = reportModel
		fields = "url"