# syntax=docker/dockerfile:1

ARG CCF_VERSION=1.0.19
FROM ccfciteam/ccf-app-ci:${CCF_VERSION}
#FROM ccfciteam/ccf-app-ci:1.0.19

ENV TERM=screen-256color

# -----------------------------------------------------------------
# Install base packages
# -----------------------------------------------------------------
ARG ADD_APT_PKGS=

ENV DEBIAN_FRONTEND "noninteractive"
RUN apt-get update \
    && apt-get install -y -q \
        python \
        python3-dev \
        python3-venv \
        python3-virtualenv \
        virtualenv \
        net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------
# -----------------------------------------------------------------
WORKDIR /project/pdo

ARG UNAME=pdo_ccf
ARG UID=1000
ARG GID=$UID

RUN echo $UID $GID
RUN groupadd -f -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -d /project/pdo -o -s /bin/bash $UNAME
RUN chown --recursive $UNAME:$UNAME /project/pdo
USER $UNAME

ENTRYPOINT ["/bin/bash"]
