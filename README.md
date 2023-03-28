`groupadd vici`
`chown root:vici /var/run/charon.vici`
`chmod 0770 /var/run/charon.vici`
`usermod -aG vici $user`
