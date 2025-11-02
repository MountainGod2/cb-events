{% if obj.display %}
.. py:{{ obj.type }}:: {{ obj.short_name }}
{%- if obj.type_annotation %}
   :canonical: {{ obj.type_annotation }}
{%- endif %}
{%- if obj.imported %}
   :noindex:
{%- endif %}

{% if obj.docstring %}
{{ obj.docstring|indent(3) }}
{% endif %}
{% endif %}
