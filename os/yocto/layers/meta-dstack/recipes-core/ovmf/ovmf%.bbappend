do_deploy:class-target:append() {
    for i in \
        ovmf \
        ovmf.code \
        ovmf.vars \
        ; do
        cp ${WORKDIR}/ovmf/$i.fd ${DEPLOYDIR}/
    done
}