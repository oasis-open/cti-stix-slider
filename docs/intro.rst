​Introduction
=================

The stix-slider is a software tool for 'sliding' STIX 2.0 JSON to STIX
1.x XML. Due to the differences between STIX 1.x and STIX 2.0, this
conversion is a best-effort only. During the conversion, stix-slider
produces many warning messages about the assumptions it needs to make to produce
valid STIX
1.x XML, and what information was not able to be converted.

It important to emphasize that the slider is not for use in a *production* system without human
inspection of the results it produces. It should be used to explore
how STIX 2.0 content could potentially be represented in STIX 1.x.
Using the current version of the slider will provide insight to issues
that might need to be mitigated to convert your STIX 2.0 content for
use in application that accept only STIX 1.x content.

