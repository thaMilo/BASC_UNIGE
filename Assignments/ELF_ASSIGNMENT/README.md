[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/Ur6o7mH2)
# ELF

The goal of this assignment is to get acquainted with the ELF file format.
Unzip `ELF_files.zip`, and you'll have a bunch of files to work with.

All of them hide a *flag*, that is, a string of the form `BASC{...}`,
where "..." is at least eight characters long. In particular, `BASC{3T0N5}`,
which is something you may come across, is not the intended flag for the
corresponding file.

In some cases, you can get the corresponding flag by merely running the program.
Other times you need to be more creative. Note that some ELF files have been
(intentionally) "corrupted", so you'll first need to understand what's wrong
with them.

Don't worry if you don't find all the flags. Analyze the ELF files, leveraging
the tools we discussed during lectures, and compare them with "normal" ELF files
you have in your system. In what they differ? Is there anything strange?

You should then write a small report briefly describing, for each ELF file, in
what it differs from a "plain x86/x64 ELF" and, if you find its flag, what you
did to discover it.
Specify which tools you used and how (if you like, you can include screenshots
to describe your workflow better).

Your report must be written in English. Please avoid MS/Open/Libre-office formats: a plain ASCII, markdown or a PDF are fine.

Add your report to your repository, before the deadline, to submit your work
(that is, in git: add, commit and push).
