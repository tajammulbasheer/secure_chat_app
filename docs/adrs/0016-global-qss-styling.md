# ADR 0016: Global QSS Dark Mode Styling

**Date:** 2026-07-10  
**Status:** Accepted

## Context
The graphical user interface (GUI) built with PyQt6 functioned correctly but suffered from a bland, inconsistent default operating system aesthetic. A modern secure chat application requires a polished, premium look and feel to build user trust and provide a good user experience. Hardcoding styles on individual widgets was unmaintainable.

## Decision
We decided to adopt a global Qt Style Sheet (QSS) approach to implement a cohesive "Dark Mode" theme across the entire application. We created `client/gui/style.qss` containing a charcoal and neon-accented color palette. We assigned specific `objectName` properties to critical widgets (e.g., `primaryButton`, `titleLabel`, `chatArea`) and applied the stylesheet centrally to the `QApplication` instance in `app.py`.

## Consequences
- **Positive**: Achieved a premium, consistent visual design. Styling logic is entirely separated from Python UI logic, improving maintainability. Future themes can be added by simply swapping the QSS file.
- **Negative**: Qt Style Sheets have some rendering quirks and limitations compared to modern web CSS. Debugging specific layout issues occasionally requires trial and error with QSS syntax.
