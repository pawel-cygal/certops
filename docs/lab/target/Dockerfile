FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ops \
    && printf 'ops ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ops \
    && chmod 0440 /etc/sudoers.d/ops

RUN mkdir -p /run/sshd /home/ops/.ssh \
    && chown -R ops:ops /home/ops/.ssh \
    && chmod 700 /home/ops/.ssh

COPY ssh/authorized_keys /home/ops/.ssh/authorized_keys
RUN chown ops:ops /home/ops/.ssh/authorized_keys \
    && chmod 600 /home/ops/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
