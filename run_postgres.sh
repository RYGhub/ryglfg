#!/bin/bash
systemctl is-active --quiet postgresql || systemctl start postgresql
