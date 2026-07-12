"""Mapping from Lazarus/LCL control classes to Qt widget classes.

Used by the .ui generator. Only visual controls become widgets; non-visual
components (timers, dialogs, menus-as-objects, data sources) are handled
separately or skipped. Unknown visual types fall back to QWidget so the layout
still reserves their space, and the generator flags them for manual attention.
"""

# LCL type -> Qt widget class.
WIDGET_MAP = {
    # windows / containers
    "TForm": "QWidget",
    "TFrame": "QWidget",
    "TPanel": "QFrame",
    "TGroupBox": "QGroupBox",
    "TScrollBox": "QScrollArea",
    "TPageControl": "QTabWidget",
    "TNotebook": "QTabWidget",
    "TTabSheet": "QWidget",
    "TTabControl": "QTabWidget",
    "TFlowPanel": "QFrame",
    "TShape": "QFrame",
    "TBevel": "QFrame",
    # buttons
    "TButton": "QPushButton",
    "TBitBtn": "QPushButton",
    "TSpeedButton": "QToolButton",
    "TColorButton": "QPushButton",
    "TToolButton": "QToolButton",
    # inputs
    "TCheckBox": "QCheckBox",
    "TRadioButton": "QRadioButton",
    "TComboBox": "QComboBox",
    "TColorBox": "QComboBox",
    "TEdit": "QLineEdit",
    "TLabeledEdit": "QLineEdit",
    "TMaskEdit": "QLineEdit",
    "TMemo": "QPlainTextEdit",
    "TSynEdit": "QPlainTextEdit",
    "TRichMemo": "QTextEdit",
    "TSpinEdit": "QSpinBox",
    "TFloatSpinEdit": "QDoubleSpinBox",
    "TTrackBar": "QSlider",
    "TProgressBar": "QProgressBar",
    "TScrollBar": "QScrollBar",
    "TUpDown": "QSpinBox",
    "TDateTimePicker": "QDateTimeEdit",
    # text / static
    "TLabel": "QLabel",
    "TStaticText": "QLabel",
    "TDBText": "QLabel",
    "TImage": "QLabel",
    "TPaintBox": "QWidget",
    # lists / grids / trees
    "TListView": "QTreeWidget",
    "TListBox": "QListWidget",
    "TCheckListBox": "QListWidget",
    "TTreeView": "QTreeWidget",
    "TStringGrid": "QTableWidget",
    "TDrawGrid": "QTableWidget",
    "TValueListEditor": "QTableWidget",
    # bars
    "TToolBar": "QToolBar",
    "TStatusBar": "QStatusBar",
    "TCoolBar": "QToolBar",
    "THeaderControl": "QHeaderView",
    # grouped radios / path pickers / custom trees + frames
    "TRadioGroup": "QGroupBox",
    "TCheckGroup": "QGroupBox",
    "TDirectoryEdit": "QLineEdit",
    "TFileNameEdit": "QLineEdit",
    "TLazVirtualStringTree": "QTreeWidget",
    "TVirtualStringTree": "QTreeWidget",
    "TframeHotkeyConfig": "QWidget",
    "TCEListView": "QTreeWidget",
}

# Non-visual components: present in the .lfm but not part of the visual layout.
# They map to behaviour (menus, timers, dialogs) and are handled separately or
# ignored by the layout generator.
NONVISUAL = {
    "TMainMenu", "TPopupMenu", "TMenuItem",
    "TTimer", "TIdleTimer", "TApplicationProperties",
    "TOpenDialog", "TSaveDialog", "TSelectDirectoryDialog",
    "TColorDialog", "TFontDialog", "TPrintDialog", "TPrinterSetupDialog",
    "TImageList", "TActionList", "TAction", "TXMLConfig", "TXMLPropStorage",
    "TIdTCPClient", "TIdTCPServer", "TProcess", "TDataSource", "TSQLQuery",
    "TFindDialog", "TReplaceDialog", "TTaskDialog", "TShellTreeView",
    "TTrayIcon", "TDatasource", "TValueListEditorColumn",
    "TOpenPictureDialog", "TSavePictureDialog", "TCalculatorDialog",
    # SynEdit internal gutter/highlighter helpers (not standalone widgets)
    "TSynGutterChanges", "TSynGutterCodeFolding", "TSynGutterLineNumber",
    "TSynGutterMarks", "TSynGutterPartList", "TSynGutterSeparator",
    "TSynCompletion", "TSynCppSyn", "TSynPasSyn", "TSynAutoComplete",
    "TSynGutterLineOverview", "TSynAnySyn", "TSynMultiSyn",
    "TSQLTransaction", "TSQLite3Connection", "TPQConnection",
}

# Splitters just partition space; we drop them from the absolute layout.
SKIP = {"TSplitter"}


def qt_class(lfm_type: str) -> str | None:
    """Return the Qt class for a visual LCL type, or None if non-visual/skipped."""
    if lfm_type in NONVISUAL or lfm_type in SKIP:
        return None
    return WIDGET_MAP.get(lfm_type)


def is_nonvisual(lfm_type: str) -> bool:
    return lfm_type in NONVISUAL or lfm_type in SKIP
