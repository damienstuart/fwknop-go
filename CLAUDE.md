# Firewall Knock Operator Written in Go (fwknop-go)

This is a version of the C-based version of the fwknop project ported to Go. This code was created
during previous Claude Code planning and execution sessions. 

# Background

For more background, the `_notes` directory contains 2 markdown files:

* fwknop-CLAUDE.md - The original CLAUDE.md file I used in the original fwknop source directory.
* development-journal.md - A summary of the planning and execution session with Claude Code to create this Go version. 

You can also find the original fwknop project in `/Users/dstuart/projects/fwknop`. Note if you end looking there, stick
only to the directories listed in the "Project/Code organization" section of the "fwknop-CLAUDE.md" file.

## Components

The main components in this project are:

* fkospa - A Go module that implements the SPA protocol and provided function to create/update SPA data, and decrypt/decode SPA data.
* fwknop - A client program for create and sending SPA requests to an fwknop server.
* fwknopd - An fwknop server implementation (currenly only receives, parses, and logs incoming SPA request)

## Goals for this project

Basic functionality works, though I did come across some issues I'd like to address - and we may come up with more
as we work through the plan.

* I want to do a thorough review of the code, and look for ways to improve and refine it consistency, readability, and functionality.
* There are some constant and variable name conventions, I think should be changed to be more in line with what they represent.
* I also want to reconsider the configuration file handling (like not worrying about supporting the legacy config file format and do YAML only).
* I will want to discuss approaches for the server functionality:
  * Presently, the server receives, processes (decrypts and decodeds), and logs incoming SPA packets.
  * The original fwknop server was hard-coded to work with a few different back-end firewall implementations (iptables, firewalld, pf, etc.) - and had a generic external command cycle for cases not covered by the built-in firewall support.  I will want to look at
  how we might architect a more generic flexible/configurable approach for the typical fwknop cycle (open firewall rule in this case):
    * Receive and parse a valid SPA request.
    * Based on the request data, execute the command to add a firewall rule to allow an incoming connection.
    * After a configured timeout, the firewall rule is removed (if it does not expire on its own).
    * In some cases, a request might be to simply execute a command (no firewall interaction,e tc).
* I will want to create and examples directory with examples for using the fkospa module.
* Expand documentation for each component - making sure all program features and options are covered.

## Misc Notes:

* Nothing is to be done until we go through plan mode to work out a plan for the items above.
* It may make sense to break these down into logical grouping and make changes in a phased approach (like save documentation for later or last stages).
* So after you read this file, and review the documents in the _notes directory, let's go into plan mode and start discussing this.