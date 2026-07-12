# Disable ncurses/cgdisk to avoid linking against libncursesw (not in our images)
PACKAGECONFIG:remove = "ncurses"
