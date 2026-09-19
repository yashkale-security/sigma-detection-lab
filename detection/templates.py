SIGMA_TEMPLATE = """title: {{ rule.title }}
id: {{ rule.technique_id | lower }}_{{ rule.test_guid | lower }}
status: test
description: {{ rule.description }}
references:
{% for ref in rule.references %}
    - {{ ref }}
{% endfor %}
author: Purple Pipeline Auto-Drafter
date: {{ rule.generated_at[:10] }}
modified: {{ rule.generated_at[:10] }}
tags:
{% for tag in rule.tags %}
    - {{ tag }}
{% endfor %}
logsource:
{% for key, value in rule.logsource.items() %}
    {{ key }}: {{ value }}
{% endfor %}
detection:
{% for key, value in rule.detection.items() %}
    {{ key }}:
{% if value is mapping %}
{% for k, v in value.items() %}
        {{ k }}:
{% if v is sequence %}
{% for item in v %}
            - {{ item }}
{% endfor %}
{% else %}
            {{ v }}
{% endif %}
{% endfor %}
{% else %}
        {{ value }}
{% endif %}
{% endfor %}
falsepositives:
{% for fp in rule.false_positive_scenarios %}
    - {{ fp }}
{% endfor %}
level: {% if rule.confidence == 'high' %}high{% else %}medium{% endif %}
confidence: {{ rule.confidence }}
fields_used:
{% for field in rule.fields_used %}
    - {{ field }}
{% endfor %}
fields_assumed:
{% for field in rule.fields_assumed %}
    - {{ field }}
{% endfor %}
"""