;;; Local source-build candidate; see SID 0011 for upstream submission gates.
;;; This recipe does not start a service or create mutable state in /gnu/store.
;;; Populate the pinned source cache with `zig build` before evaluating it.
;;; GUIX_SIBUNA_ZIG may name a source-built Zig 0.17.0 package in a pinned channel.
;;; Then: guix build -f guix.scm; guix package -f guix.scm

(use-modules (guix packages)
             (guix gexp)
             (guix git-download)
             (guix build-system gnu)
             ((guix licenses) #:prefix license:)
             (gnu packages)
             (gnu packages base)
             (gnu packages node)
             (gnu packages python)
             (ice-9 ftw)
             (srfi srfi-1)
             (srfi srfi-13))

(define root (dirname (canonicalize-path (current-filename))))
(define tracked-file?
  (or (git-predicate root)
      (error "The local Guix candidate requires a Git checkout")))

(define (source-file? file stat)
  ;; Include build inputs and corresponding source, but no private state or caches.
  (let* ((relative (if (string=? file root) ""
                       (substring file (+ 1 (string-length root)))))
         (parts (string-split relative #\/)))
    (and (or (string-null? relative)
             (tracked-file? file stat)
             (member relative '("guix.scm" "SECURITY.md"
                                "tools/prepare_distribution_source.py"
                                "docs/sid/records/0011-distribution-packages.typ")))
         (or (string-null? relative)
             (member (car parts)
                     '("build.zig" "build.zig.zon" "build" "apps" "benchmarks"
                       "libs" "tools" "vendor" "docs" "distribution" "README.md" "LICENSE"
                       "LICENSES" "NOTICE" "SECURITY.md" "CONTRIBUTING.md" "guix.scm")))
         (not (any (lambda (part)
                     (or (string-prefix? "." part)
                         (member part '("node_modules" "zig-out" "__pycache__"))))
                   parts))
         (not (string-prefix? "docs/build" relative))
         (not (eq? 'symlink (stat:type stat))))))

(define (cached-source hash files)
  (let ((path (string-append root "/zig-pkg/" hash)))
    (unless (file-exists? path)
      (error "Missing pinned amalgamation: run zig build before guix build" hash))
    (local-file path #:recursive? #t
                #:select? (lambda (file stat)
                            (or (string=? file path)
                                (and (eq? 'regular (stat:type stat))
                                     (member (basename file) files)))))))

(define zig-toolchain
  (specification->package (or (getenv "GUIX_SIBUNA_ZIG") "zig@0.17.0")))

(unless (string=? (package-version zig-toolchain) "0.17.0")
  (error "Sibuna requires a source-built Zig 0.17.0 package"))

(package
  (name "sibuna")
  (version "0.3.3")
  (source (local-file root "sibuna-source" #:recursive? #t #:select? source-file?))
  ;; Explicit phases avoid older zig-build-system optimization spellings and
  ;; retain Guix's native libc paths rather than a foreign binary loader.
  (build-system gnu-build-system)
  (arguments
   '(#:tests? #t
     #:strip-binaries? #f
     #:phases
     (modify-phases %standard-phases
       (delete 'configure)
       (add-after 'unpack 'prepare-offline-build
         (lambda* (#:key inputs #:allow-other-keys)
           (setenv "ZIG_GLOBAL_CACHE_DIR" (string-append (getcwd) "/.zig-global-cache"))
           (invoke "python3" "tools/prepare_distribution_source.py"
                   "--root" "." "--sqlite" (assoc-ref inputs "sqlite-source")
                   "--sqlite-vec" (assoc-ref inputs "sqlite-vec-source"))
           (invoke "python3" "tools/check_release_version.py")
           (invoke "python3" "tools/console_assets.py" "check")
           ;; Zig 0.17 requires all libc fields, including the GCC runtime and
           ;; an empty Darwin SDK field. Detect them through Guix's native CC.
           (invoke "python3" "-c"
                   "import pathlib, subprocess; pathlib.Path('.guix-libc.conf').write_bytes(subprocess.check_output(['zig', 'libc']))")
           (setenv "GUIX_SIBUNA_DYNAMIC_LINKER"
                   (string-append (assoc-ref inputs "libc") "/lib/"
                                  (if (string=? (utsname:machine (uname)) "x86_64")
                                      "ld-linux-x86-64.so.2"
                                      "ld-linux-aarch64.so.1")))))
       (replace 'build
         (lambda _
           (invoke "zig" "build" "-Doptimize=safe" "-Dstrip=true"
                   "-Dstorage=true" "-Dconsole=true" "-Dcluster=false"
                   "-Dcpu=baseline"
                   (string-append "-Ddynamic-linker=" (getenv "GUIX_SIBUNA_DYNAMIC_LINKER"))
                   "--libc" ".guix-libc.conf" "-j2")))
       (replace 'check
         (lambda* (#:key tests? #:allow-other-keys)
           (when tests?
             (invoke "zig" "build" "test" "-Doptimize=safe"
                     "-Dstorage=true" "-Dconsole=true" "-Dcluster=false"
                     "-Dcpu=baseline"
                     (string-append "-Ddynamic-linker=" (getenv "GUIX_SIBUNA_DYNAMIC_LINKER"))
                     "--libc" ".guix-libc.conf" "-j2")
             (invoke "python3" "tools/check_release_version.py" "zig-out/bin/sibuna"))))
       (replace 'install
         (lambda* (#:key outputs #:allow-other-keys)
           (let* ((out (assoc-ref outputs "out"))
                  (doc (string-append out "/share/doc/sibuna")))
             (install-file "zig-out/bin/sibuna" (string-append out "/bin"))
             (for-each (lambda (file) (install-file file doc))
                       '("README.md" "LICENSE" "NOTICE" "SECURITY.md"))
             (copy-recursively "LICENSES" (string-append doc "/LICENSES"))))))))
  (native-inputs
   `(("zig" ,zig-toolchain)
     ("python" ,python)
     ("node" ,node)
     ("sqlite-source" ,(cached-source "N-V-__8AAHCbqABM_X5RTjbDBDBWErxZE8tJzmtEnLOLRHGx"
                                     '("shell.c" "sqlite3.c" "sqlite3.h" "sqlite3ext.h")))
     ("sqlite-vec-source" ,(cached-source "N-V-__8AAFjlBACTHqSZPx-m0Y-NHDBK6_c28UfnIp9rxqgX"
                                         '("sqlite-vec.c" "sqlite-vec.h")))))
  (inputs (list (list "libc" glibc)))
  (supported-systems '("x86_64-linux" "aarch64-linux"))
  (home-page "https://github.com/insanai/sibuna")
  (synopsis "Web protection reverse proxy with browser proof of work")
  (description
   "Sibuna protects web applications using browser proof of work, declarative
access rules, semantic inspection and optional native OWASP Core Rule Set
evaluation.  This package includes persistent storage and the management console;
clustering is disabled.  Operators provision secrets and enable services separately.")
  (license (list license:agpl3 license:lgpl3)))
