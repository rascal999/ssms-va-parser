#!/usr/bin/env bash

# Critical conversion
sed -i 's#\\vulntext{Critical}#\\vulntext{10}#g' ssms-output/*.tex
# High conversion
sed -i 's#\\vulntext{High}#\\vulntext{8}#g' ssms-output/*.tex
# Medium conversion
sed -i 's#\\vulntext{Medium}#\\vulntext{5.5}#g' ssms-output/*.tex
# Low conversion
sed -i 's#\\vulntext{Low}#\\vulntext{2}#g' ssms-output/*.tex
# Info conversion
sed -i 's#\\vulntext{Info}#\\vulntext{1}#g' ssms-output/*.tex
