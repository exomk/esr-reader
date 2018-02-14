/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (C) 2018  EXO Service Solutions
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * You can contact us at contact4exo@exo.mk
 */

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>

void log_info(const char *info)
{
    openlog ("registrator", LOG_PID|LOG_CONS, LOG_USER);
    syslog (LOG_INFO,"%s", info);
    closelog ();
}

void log_info_message(const char *info, const char *message)
{
    openlog ("registrator", LOG_PID|LOG_CONS, LOG_USER);
    syslog (LOG_INFO,"%s %s", info, message);
    closelog ();
}

void log_error(const char *message)
{
    openlog ("registrator", LOG_PID|LOG_CONS, LOG_USER);
    syslog (LOG_ERR, "%s", message);
    closelog ();
}

void log_error_msg_err(const char *message, const char *error)
{
    openlog ("registrator", LOG_PID|LOG_CONS, LOG_USER);
    syslog (LOG_ERR,"%s %s", message, error);
    closelog ();
}


