FROM python:3.9-slim-buster

WORKDIR /app

COPY run-jira-sync.sh jira-case-sync.py JIRA.py STELLAR_UTIL.py LOGGER_UTIL.py requirements.txt /app

RUN mkdir -p /app/data
RUN chmod o+rwx /app/run-jira-sync.sh

RUN pip install --no-cache-dir -r requirements.txt

# CMD ["python", "jira-case-sync.py", "-d"]
CMD ["/app/run-jira-sync.sh"]
