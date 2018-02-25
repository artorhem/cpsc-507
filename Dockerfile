FROM python:2

COPY ./src /
ADD requirements.txt /

RUN pip install -r requirements.txt


CMD python /cli.py --url 'https://github.com/scholtzan/cpsc-507'
