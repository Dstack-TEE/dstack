FROM nvidia/cuda:12.4.0-devel-ubuntu20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Add deadsnakes PPA to get Python 3.10
RUN apt-get update && apt-get install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa

# Install Python 3.10 and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 \
    python3.10-distutils \
    python3.10-venv \
    curl \
    ca-certificates \
    build-essential \
    cmake \
    git \
    libjpeg-dev \
    libpng-dev \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Update alternatives to use Python 3.10
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1

# Install pip for Python 3.10
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.10

# Install Python packages
RUN python3 -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124
RUN python3 -m pip install jupyterlab networkx six

# Create a working directory
WORKDIR /workspace

# Expose the port JupyterLab will be accessible on
EXPOSE 8888

# Command to start JupyterLab
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]
