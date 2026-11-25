# Training profile: CUDA PyTorch. Needs a GPU worker (NVIDIA driver + container toolkit) to use the GPU;
# runs on CPU otherwise. NOT built in the authoring environment (multi-GB image, registry rate limits).
FROM pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    pip install --no-cache-dir transformers datasets accelerate peft safetensors && rm -rf /root/.cache \
 && groupadd -g 10001 sandbox && useradd -u 10001 -g 10001 -d /home/sandbox -s /bin/bash sandbox \
 && mkdir -p /workspace /home/sandbox && chown 10001:10001 /workspace /home/sandbox
ENV HF_HOME=/workspace/.hf
USER 10001:10001
WORKDIR /workspace
CMD ["sleep", "infinity"]
