.. index:: ! psscale
.. include:: module_core_purpose.rst_

*******
psscale
*******

|psscale_purpose|

Synopsis
--------

.. include:: common_SYN_OPTs.rst_

**gmt psscale**
[ |SYN_OPT-B| ]
[ |-C|\ *cpt* ]
[ |-D|\ *refpoint* ]
[ |-F|\ *panel* ]
[ |-G|\ *zlo*\ /\ *zhi* ]
[ |-I|\ [*max\_intens*\|\ *low_i*/*high_i*] ]
[ |-J|\ *parameters* ]
[ |-K| ]
[ |-L|\ [**i**][*gap*] ]
[ |-M| ]
[ |-N|\ [**p**\|\ *dpi* ]]
[ |-O| ]
[ |-P| ] [ |-Q| ]
[ |SYN_OPT-R| ]
[ |-S|\ [**+a**\ *angle*][**+c**\|\ **n**\ ][**+s**][**+x**\ *label*][**+y**\ *unit*] ]
[ |SYN_OPT-U| ]
[ |SYN_OPT-V| ]
[ |-W|\ *scale* ]
[ |SYN_OPT-X| ]
[ |SYN_OPT-Y| ]
[ |-Z|\ *widthfile* ]
[ |SYN_OPT-p| ]
[ |SYN_OPT-t| ]
[ |SYN_OPT--| ]

.. include:: colorbar.rst
    :start-after: .. module_common_begins
    :end-before: .. module_common_ends

.. include:: common_classic.rst_

Examples
--------

.. include:: explain_example.rst_

To plot a horizontal color scale (12 cm long; 0.5 cm wide) at the reference point (8,1)
(paper coordinates) with justification at top center and automatic annotation interval, do

   ::

    gmt makecpt -T-200/1000/100 -Crainbow > t.cpt
    gmt psscale -Ct.cpt -Dx8c/1c+w12c/0.5c+jTC+h -Bxaf+l"topography" -By+lkm -P > map.ps


To append a vertical color scale (7.5 cm long; 1.25 cm wide) to the
right of a plot that is 6 inch wide and 4 inch high, using illumination,
and show back- and foreground colors, and annotating every 5 units, we
provide the reference point and select the left-mid anchor point via

   ::

    gmt psscale -Dx6.5i+jLM/2i+w7.5c/1.25c+e -O -Ccolors.cpt -I -Bx5+lBATHYMETRY -By+lm >> map.ps

To overlay a horizontal color scale (4 inches long and default width) above a
Mercator map produced by a previous call, ensuring a 2 cm offset from the map frame, use

   ::

    gmt psscale -DjCT+w4i+o0/2c+h -O -Ccolors.cpt -Baf -R -J >> map.ps

.. include:: colorbar.rst
    :start-after: .. module_note_begins
    :end-before: .. module_note_ends

See Also
--------

:doc:`gmt`, :doc:`makecpt`
:doc:`gmtlogo`, :doc:`grd2cpt`
:doc:`psimage`, :doc:`pslegend`
