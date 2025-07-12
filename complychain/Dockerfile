FROM python:3.10-slim
RUN pip install complychain
COPY audit_server.py .

# Configure volume for persistent audit chain
VOLUME /audit_chain

# Set environment variables for GLBA compliance
ENV GLBA_COMPLIANCE_MODE=strict
ENV AUDIT_CHAIN_DIR=/audit_chain

CMD ["python", "audit_server.py", "--data-dir=/audit_chain"] 