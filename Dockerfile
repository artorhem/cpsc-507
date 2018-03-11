FROM python

COPY ./src /
ADD requirements.txt /
ADD scripts/execute-analysis.sh execute-analysis.sh 

RUN apt-get -y update
RUN apt-get install -y --fix-missing \
    build-essential \
    cmake \
    gfortran \
    git \
    wget \
    g++ \
    curl \
    graphicsmagick \
    libgraphicsmagick1-dev \
    libgl1-mesa-glx \
    libhdf5-dev \
    openmpi-bin \
    libatlas-dev \
    libavcodec-dev \
    libavformat-dev \
    libgtk2.0-dev \
    libjpeg-dev \
    liblapack-dev \
    libswscale-dev \
    pkg-config \
    python3-dev \
    python3-numpy \
    bzip2 \
    software-properties-common \
    zip

RUN pip install -r requirements.txt
RUN chmod +x execute-analysis.sh 

CMD ./execute-analysis.sh
