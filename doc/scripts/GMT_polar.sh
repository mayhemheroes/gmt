#!/usr/bin/env bash
gmt begin GMT_polar
	gmt set GMT_THEME cookbook
	gmt grdmath -R0/360/2/4 -I6/0.1 X 4 MUL PI MUL 180 DIV COS Y 2 POW MUL = tt.nc
	gmt grdcontour tt.nc -JP8c -B30 -BNs+ghoneydew -C2 -S4 --FORMAT_GEO_MAP=+ddd
gmt end show
