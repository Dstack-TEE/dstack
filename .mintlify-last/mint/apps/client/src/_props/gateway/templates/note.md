# Reference Implementation: Original RProxy Configuration

This document contains the reference implementation of the original RProxy configuration template. Due to version incompatibilities between the current RProxy library and its documentation, this implementation has been preserved in `rproxy.yaml.backup` for archival purposes.

The production configuration can be found in `rproxy.yaml`, which contains the necessary modifications to ensure compatibility with the current RProxy library version while maintaining the same core functionality.

gateway/templates/rproxy.yaml

```yaml
servers:
  {%- for p in portmap %}
  - type: socket
    listen: {{ p.listen_addr }}:{{ p.listen_port }}
    handler:
      type: lazytls
      certificate: {{ cert_chain }}
      key: {{ cert_key }}
      sni: {% if peers.is_empty() -%}
      []
      {% else -%}
      {% for peer in peers %}
        - hostname: {{ peer.id }}.{{ base_domain }}
          certificate: {{ cert_chain }}
          key: {{ cert_key }}
          handler:
            type: tunnel
            target: {{ peer.ip }}:{{ p.target_port }}
      {% endfor %}
      {%- endif %}
  {%- endfor %}
```
