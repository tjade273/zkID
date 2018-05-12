(TeX-add-style-hook
 "paper"
 (lambda ()
   (TeX-add-to-alist 'LaTeX-provided-class-options
                     '(("extarticle" "11pt")))
   (TeX-add-to-alist 'LaTeX-provided-package-options
                     '(("geometry" "margin=1in") ("enumitem" "shortlabels" "inline") ("babel" "english") ("natbib" "numbers")))
   (TeX-run-style-hooks
    "latex2e"
    "extarticle"
    "extarticle11"
    "geometry"
    "amsmath"
    "amsthm"
    "amssymb"
    "enumitem"
    "mleftright"
    "array"
    "gensymb"
    "babel"
    "setspace"
    "pgfplots"
    "booktabs"
    "natbib"
    "todonotes"
    "tikz-cd"
    "mathtools")
   (TeX-add-symbols
    '("vectorproj" ["argument"] 1)
    "mdoubleplus"
    "vect"
    "N"
    "Z"
    "R"
    "C"
    "Q"
    "Mat"
    "sgn"
    "Char"
    "defeq"
    "hom")
   (LaTeX-add-environments
    '("corollary" LaTeX-env-args ["argument"] 1)
    '("proposition" LaTeX-env-args ["argument"] 1)
    '("reflection" LaTeX-env-args ["argument"] 1)
    '("exercise" LaTeX-env-args ["argument"] 1)
    '("theorem" LaTeX-env-args ["argument"] 1)
    '("amatrix" 1)
    "theorem")
   (LaTeX-add-bibliographies
    "Identity")
   (LaTeX-add-amsthm-newtheorems
    "lemma")
   (LaTeX-add-mathtools-DeclarePairedDelimiters
    '("norm" "")))
 :latex)

