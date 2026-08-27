# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

FROM python:3.12-slim
WORKDIR /app
COPY server.py /app/server.py
EXPOSE 8080/tcp 53/udp 53/tcp
CMD ["python", "/app/server.py"]
