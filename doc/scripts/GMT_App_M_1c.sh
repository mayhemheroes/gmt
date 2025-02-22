#!/usr/bin/env bash
#
#	Makes the insets for Appendix M(cpt)
#	[skip srtm which is just a special version of dem2]
#
# We have five sets of CPT figures to make:
# 1a) Our regular, traditional GMT CPTs [44]
# 1b) The regular Scientific Color Maps* [30]
# 1c) Categorical CPTs [18]
# 1d) Cyclic CPTs [7]
# 1e) Colormaps from cmocean [22]
#
# *from Fabio [www.fabiocrameri.ch/visualisation]

GMT_SHAREDIR=$(gmt --show-sharedir)

# Here we list all the categorical cpts (Leaving out c|C in Categorical since cases vary):
sed -e 's/"//g' "${GMT_SOURCE_DIR}"/src/gmt_cpt_masters.h | egrep ategorical | awk '{print $1}' | sort -r > tt.lis

n=$(cat tt.lis | wc -l)
let n2=n/2
let n2=n
# dy is line spacing and y0 is total box height
dy=0.6
y0=$(gmt math -Q $n2 $dy MUL 0.5 MUL 0.1 ADD =)

gmt begin GMT_App_M_1c
gmt set GMT_THEME cookbook
gmt set MAP_FRAME_PEN thinner FONT_ANNOT_PRIMARY 8p MAP_TICK_LENGTH_PRIMARY 0.1i MAP_ANNOT_OFFSET_PRIMARY 0.04i
gmt basemap -R0/6.1/0/$y0 -Jx1i -B0

i=1
y=0.375
y2=0.25
while [ $i -le $n2 ]
do
	j1=$(expr $n2 - $i)
	j2=$(expr $n2 - $i + 1)
	left=$(sed -n ${j1}p tt.lis)
	right=$(sed -n ${j2}p tt.lis)
	gmt makecpt -H -C$left > tt.left.cpt
	gmt makecpt -H -C$left -T-1/1/0.25 > tt.left2.cpt
	gmt makecpt -H -C$right > tt.right.cpt
	gmt makecpt -H -C$right -T-1/1/0.25 > tt.right2.cpt
	gmt colorbar -Dx1.55i/${y}i+w2.70i/0.125i+h+jTC -Ctt.left.cpt -B0
	gmt colorbar -Dx4.50i/${y}i+w2.70i/0.125i+h+jTC -Ctt.right.cpt -B0
	gmt colorbar -Dx1.55i/${y2}i+w2.70i/0.125i+h+jTC -Ctt.left2.cpt -Bf0.25
	gmt colorbar -Dx4.50i/${y2}i+w2.70i/0.125i+h+jTC -Ctt.right2.cpt -Bf0.25
	gmt text -D0/0.05i -F+f9p,Helvetica-Bold+jBC <<- END
	1.55 $y ${left}
	4.50 $y ${right}
	END
	if [ $(grep -c HARD_HINGE ${GMT_SHAREDIR}/cpt/${left}.cpt) -eq 1 ]; then # Plot hard hinge symbol for left CPT
		echo 1.55 $y | gmt plot -St0.2c -Gblack -Wfaint -D0/-0.29i
	elif [ $(grep -c SOFT_HINGE ${GMT_SHAREDIR}/cpt/${left}.cpt) -eq 1 ]; then # Plot soft hinge symbol for left CPT
		echo 1.55 $y | gmt plot -St0.2c -Gwhite -Wfaint -D0/-0.29i
	fi
	if [ $(grep -c HARD_HINGE ${GMT_SHAREDIR}/cpt/${right}.cpt) -eq 1 ]; then # Plot hard hinge symbol for right CPT
		echo 4.50 $y | gmt plot -St0.2c -Gblack -Wfaint -D0/-0.29i
	elif [ $(grep -c SOFT_HINGE ${GMT_SHAREDIR}/cpt/${right}.cpt) -eq 1 ]; then # Plot soft hinge symbol for right CPT
		echo 4.50 $y | gmt plot -St0.2c -Gwhite -Wfaint -D0/-0.29i
	fi
	i=$(expr $i + 2)
	y=$(gmt math -Q $y $dy ADD =)
	y2=$(gmt math -Q $y2 $dy ADD =)
done
rm -f tt.*
gmt end show
