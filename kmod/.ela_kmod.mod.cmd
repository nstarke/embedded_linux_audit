savedcmd_ela_kmod.mod := printf '%s\n'   ela_kmod.o | awk '!x[$$0]++ { print("./"$$0) }' > ela_kmod.mod
