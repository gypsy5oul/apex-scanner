# Use the minimal UBI image for a smaller footprint
FROM registry.access.redhat.com/ubi8/ubi-minimal

# Set the environment variable for non-interactive commands
ENV container=docker

# Install rsync and openssh-server, and necessary utilities
RUN microdnf update && \
    microdnf install -y rsync openssh-server openssh-clients passwd hostname which && \
    microdnf clean all

# --- Configuration for SSH Keys and User ---

# 1. Create a non-root user
# 1. Create a non-root user with explicit UID
RUN useradd -u 1001 -m -s /bin/bash rsyncuser && \
    echo 'rsyncuser:password' | chpasswd

# 2. Configure SSH directory for the user
RUN mkdir -p /home/rsyncuser/.ssh && \
    chown -R rsyncuser:rsyncuser /home/rsyncuser/.ssh && \
    chmod 700 /home/rsyncuser/.ssh

# 3. Generate SSH key pair
RUN ssh-keygen -t rsa -b 4096 -C "rsync-image-key" -f /home/rsyncuser/.ssh/id_rsa -q -N "" && \
    cat /home/rsyncuser/.ssh/id_rsa.pub > /home/rsyncuser/.ssh/authorized_keys && \
    chmod 600 /home/rsyncuser/.ssh/id_rsa /home/rsyncuser/.ssh/authorized_keys && \
    chown rsyncuser:rsyncuser /home/rsyncuser/.ssh/id_rsa /home/rsyncuser/.ssh/authorized_keys

# 4. Configure SSH Server - CHANGE PORT TO 2222
RUN sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config && \
    # Configure PidFile to run/sshd which we make writable
    echo "PidFile /run/sshd/sshd.pid" >> /etc/ssh/sshd_config && \
    # OCP Fix: Disable StrictModes because we must make .ssh group-writable
    echo "StrictModes no" >> /etc/ssh/sshd_config && \
    # OCP Fix: Disable PAM properly (sed because first occurrence wins)
    sed -i 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config && \
    # IMPORTANT: Change ownership of sshd directories so non-root can run sshd
    mkdir -p /run/sshd /rsync_data && \
    chown -R rsyncuser:rsyncuser /etc/ssh /run/sshd /rsync_data && \
    # OCP Fix: Allow Group 0 (root group) to write, as OCP runs as random UID in GID 0
    chgrp -R 0 /home/rsyncuser /run/sshd /etc/ssh /rsync_data && \
    chmod -R g+w /home/rsyncuser /run/sshd /etc/ssh /rsync_data

# Create a data directory
# Data directory created above


# Set the default user and expose SSH port
USER 1001
EXPOSE 2222

# Start SSH server on non-privileged port, generate host keys at runtime
CMD ["/bin/bash", "-c", "rm -f /etc/ssh/ssh_host_*_key && ssh-keygen -A && exec /usr/sbin/sshd -D -e"]
