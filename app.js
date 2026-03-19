/**
 * PyroScroll — app.js
 *
 * ────────────────────────────────────────────────────────────────
 * FIRESTORE security rules (paste into Firebase console):
 * ────────────────────────────────────────────────────────────────
 * rules_version = '2';
 * service cloud.firestore {
 *   match /databases/{database}/documents {
 *     function role() {
 *       return get(/databases/$(database)/documents/roles/$(request.auth.uid)).data.role;
 *     }
 *     function canPost() { return role() == 'owner' || role() == 'teacher'; }
 *
 *     match /users/{uid} {
 *       allow read:  if request.auth != null;
 *       allow write: if request.auth.uid == uid;
 *     }
 *     match /roles/{uid} {
 *       allow read:  if request.auth != null;
 *       allow write: if role() == 'owner';
 *     }
 *     match /announcements/{id} {
 *       allow read:   if true;
 *       allow create: if canPost();
 *       allow update: if canPost() && (resource.data.authorId == request.auth.uid || role() == 'owner');
 *       allow delete: if resource.data.authorId == request.auth.uid || role() == 'owner';
 *     }
 *   }
 * }
 *
 * ────────────────────────────────────────────────────────────────
 * STORAGE security rules (paste into Firebase console → Storage):
 * ────────────────────────────────────────────────────────────────
 * rules_version = '2';
 * service firebase.storage {
 *   match /b/{bucket}/o {
 *     match /media/{userId}/{fileName} {
 *       // Anyone can read uploaded media (announcements are public)
 *       allow read: if true;
 *       // Only the authenticated uploader can write to their folder
 *       allow create: if request.auth != null
 *                     && request.auth.uid == userId
 *                     && request.resource.size  < 100 * 1024 * 1024
 *                     && (request.resource.contentType.matches('image/.*')
 *                         || request.resource.contentType.matches('video/.*'));
 *       // Uploader or (via server-side logic) owner can delete
 *       allow delete: if request.auth != null && request.auth.uid == userId;
 *     }
 *   }
 * }
 */

/* ════════════════════════════════════════════════════════════
   IMPORTS
════════════════════════════════════════════════════════════ */
import { initializeApp }    from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAnalytics }     from "https://www.gstatic.com/firebasejs/10.12.2/firebase-analytics.js";
import {
  getAuth, GoogleAuthProvider,
  signInWithPopup, signOut as fbSignOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, collection, doc,
  addDoc, setDoc, getDoc, getDocs, deleteDoc, updateDoc,
  query, orderBy, where, onSnapshot, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import {
  getStorage, ref as storageRef,
  uploadBytesResumable, getDownloadURL, deleteObject
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

/* ════════════════════════════════════════════════════════════
   CONSTANTS
════════════════════════════════════════════════════════════ */
const FIREBASE_CONFIG = {
  apiKey:            "AIzaSyBsFs1qrmojBkuwIynMrFUYmt5NovALDoo",
  authDomain:        "pyro-scroll.firebaseapp.com",
  projectId:         "pyro-scroll",
  storageBucket:     "pyro-scroll.firebasestorage.app",
  messagingSenderId: "422391668810",
  appId:             "1:422391668810:web:847b8f56e3aedc8430c6b3",
  measurementId:     "G-TW76D61P81"
};

const OWNER_EMAIL    = "oleksandr.lahoza.24@phcol.ie";
const IMG_MAX_BYTES  = 10 * 1024 * 1024;   // 10 MB
const VID_MAX_BYTES  = 100 * 1024 * 1024;  // 100 MB
const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const ALLOWED_VIDEO_TYPES = ["video/mp4", "video/webm", "video/quicktime"];
const ALLOWED_TYPES  = [...ALLOWED_IMAGE_TYPES, ...ALLOWED_VIDEO_TYPES];

/* ════════════════════════════════════════════════════════════
   FIREBASE INIT
════════════════════════════════════════════════════════════ */
const fbApp    = initializeApp(FIREBASE_CONFIG);
getAnalytics(fbApp);
const auth     = getAuth(fbApp);
const db       = getFirestore(fbApp);
const storage  = getStorage(fbApp);
const provider = new GoogleAuthProvider();
provider.setCustomParameters({ hd: "phcol.ie" });

/* ════════════════════════════════════════════════════════════
   APP STATE
════════════════════════════════════════════════════════════ */
let currentUser       = null;
let userRole          = null;       // 'owner' | 'teacher' | null
let allAnnouncements  = [];
let currentFilter     = "all";
let searchQuery       = "";
let formMode          = "create";   // 'create' | 'edit'
let editingId         = null;

// ── Media upload state ──
// These are cleared every time the form opens/closes.
let pendingFile       = null;       // File object chosen by user
let pendingPreviewUrl = null;       // Blob URL for local preview (revoked on clear)
let activeUploadTask  = null;       // UploadTask — kept so we can cancel on form close
// When editing an announcement that already has media:
let existingMediaUrl  = null;
let existingMediaPath = null;
let existingMediaType = null;
let removeExisting    = false;      // true → delete old file on next save

let unsubRoleListener = null;
let unsubTeachers     = null;

/* ════════════════════════════════════════════════════════════
   DOM REFERENCES
════════════════════════════════════════════════════════════ */
const $  = id  => document.getElementById(id);
const $$ = sel => document.querySelectorAll(sel);

const elBtnLogin        = $("btnLogin");
const elBtnLoginPrompt  = $("btnLoginPrompt");
const elBtnSignOut      = $("btnSignOut");
const elBtnAdmin        = $("btnAdmin");
const elBtnNewPost      = $("btnNewPost");
const elBtnCancelForm   = $("btnCancelForm");
const elBtnPostSubmit   = $("btnPostSubmit");
const elBtnAddTeacher   = $("btnAddTeacher");
const elBtnCloseAdmin   = $("btnCloseAdmin");
const elUserChip        = $("userChip");
const elUserAvatar      = $("userAvatar");
const elUserName        = $("userName");
const elUserRoleBadge   = $("userRoleBadge");
const elPostFormWrap    = $("postFormWrap");
const elLoginPrompt     = $("loginPrompt");
const elAnnList         = $("annList");
const elEmptyState      = $("emptyState");
const elAdminModal      = $("adminModal");
const elSearchInput     = $("searchInput");
const elFTitle          = $("fTitle");
const elFCategory       = $("fCategory");
const elFBody           = $("fBody");
const elFExpiry         = $("fExpiry");
const elFAttachment     = $("fAttachment");
const elFormCardTitle   = $("formCardTitle");
const elCharCount       = $("charCount");
const elTeacherList     = $("teacherList");
const elTeacherEmail    = $("teacherEmailInput");
const elAddFeedback     = $("addFeedback");
const elPageSubText     = $("pageSubText");

// Media upload UI
const elUploadZone         = $("uploadZone");
const elFMedia             = $("fMedia");
const elBtnBrowseMedia     = $("btnBrowseMedia");
const elUploadPreview      = $("uploadPreview");
const elUploadPreviewMedia = $("uploadPreviewMedia");
const elPreviewFileName    = $("previewFileName");
const elPreviewFileSize    = $("previewFileSize");
const elBtnRemoveMedia     = $("btnRemoveMedia");
const elUploadProgress     = $("uploadProgress");
const elUploadProgressFill = $("uploadProgressFill");
const elUploadProgressPct  = $("uploadProgressPct");

/* ════════════════════════════════════════════════════════════
   AUTHENTICATION
════════════════════════════════════════════════════════════ */
async function signInWithGoogle() {
  try {
    await signInWithPopup(auth, provider);
  } catch (e) {
    if (e.code !== "auth/popup-closed-by-user") {
      showToast("Sign-in failed. Please try again.");
    }
  }
}

async function signOutUser() {
  await fbSignOut(auth);
  showToast("You have been signed out.");
}

onAuthStateChanged(auth, async user => {
  currentUser = user;
  if (unsubRoleListener) { unsubRoleListener(); unsubRoleListener = null; }

  if (user) {
    // Register user record (needed for teacher lookup by email)
    try {
      await setDoc(doc(db, "users", user.uid), {
        uid:         user.uid,
        email:       user.email.toLowerCase(),
        displayName: user.displayName || "",
        photoURL:    user.photoURL    || "",
        lastSeen:    serverTimestamp()
      }, { merge: true });
    } catch { /* non-critical */ }

    // Stamp owner role on every sign-in (prevents accidental removal)
    if (user.email.toLowerCase() === OWNER_EMAIL.toLowerCase()) {
      try {
        await setDoc(doc(db, "roles", user.uid), {
          email:       user.email,
          displayName: user.displayName || "",
          photoURL:    user.photoURL    || "",
          role:        "owner",
          assignedAt:  serverTimestamp()
        }, { merge: true });
      } catch { /* non-critical */ }
    }

    // Live role listener — updates UI immediately if owner changes role
    unsubRoleListener = onSnapshot(doc(db, "roles", user.uid), snap => {
      userRole = snap.exists() ? snap.data().role : null;
      refreshUI();
    });
  } else {
    userRole = null;
    refreshUI();
  }
});

/* ════════════════════════════════════════════════════════════
   UI REFRESH
════════════════════════════════════════════════════════════ */
function refreshUI() {
  const loggedIn = !!currentUser;
  const canPost  = userRole === "owner" || userRole === "teacher";
  const isOwner  = userRole === "owner";

  if (loggedIn) {
    elUserChip.style.display    = "inline-flex";
    elUserAvatar.src            = currentUser.photoURL || "";
    elUserAvatar.style.display  = currentUser.photoURL ? "" : "none";
    elUserName.textContent      = firstWord(currentUser.displayName) || "User";
    const roleLbl               = isOwner ? "Owner" : userRole === "teacher" ? "Teacher" : "";
    elUserRoleBadge.textContent = roleLbl;
    elUserRoleBadge.className   = "role-badge " + (isOwner ? "role-owner" : userRole === "teacher" ? "role-teacher" : "");
    elBtnSignOut.style.display  = "block";
    elBtnLogin.style.display    = "none";
  } else {
    elUserChip.style.display    = "none";
    elBtnSignOut.style.display  = "none";
    elBtnLogin.style.display    = "inline-flex";
  }

  elLoginPrompt.style.display = loggedIn ? "none" : "flex";
  elBtnNewPost.style.display  = canPost  ? "inline-flex" : "none";
  elBtnAdmin.style.display    = isOwner  ? "inline-flex" : "none";

  if (!loggedIn) {
    elPageSubText.textContent = "Official communications from staff.";
  } else if (isOwner) {
    elPageSubText.textContent = "Welcome, Administrator. Full access granted.";
  } else if (userRole === "teacher") {
    elPageSubText.textContent = `Welcome, ${firstWord(currentUser.displayName)}. You may post announcements.`;
  } else {
    elPageSubText.textContent = `Signed in as ${currentUser.email}. Contact an admin for posting access.`;
  }

  renderFiltered();
}

/* ════════════════════════════════════════════════════════════
   MEDIA UPLOAD — FILE SELECTION & PREVIEW
════════════════════════════════════════════════════════════ */

/**
 * Validate and stage a File for upload.
 * Shows local preview; actual upload happens on form submit.
 */
function handleFileSelection(file) {
  if (!file) return;

  // Type check
  if (!ALLOWED_TYPES.includes(file.type)) {
    showToast("Unsupported file type. Please use JPEG, PNG, GIF, WebP, MP4, WebM, or MOV.");
    return;
  }

  // Size check
  const isVideo = ALLOWED_VIDEO_TYPES.includes(file.type);
  const limit   = isVideo ? VID_MAX_BYTES : IMG_MAX_BYTES;
  if (file.size > limit) {
    showToast(isVideo ? "Video must be under 100 MB." : "Image must be under 10 MB.");
    return;
  }

  // Clear any previously staged file
  clearPendingMedia();

  pendingFile       = file;
  pendingPreviewUrl = URL.createObjectURL(file);

  // Build preview element (img or video)
  elUploadPreviewMedia.innerHTML = "";
  if (isVideo) {
    const vid = document.createElement("video");
    vid.src      = pendingPreviewUrl;
    vid.controls = true;
    vid.preload  = "metadata";
    elUploadPreviewMedia.appendChild(vid);
  } else {
    const img = document.createElement("img");
    img.src = pendingPreviewUrl;
    img.alt = "";
    elUploadPreviewMedia.appendChild(img);
  }

  elPreviewFileName.textContent = file.name;
  elPreviewFileSize.textContent = formatBytes(file.size);

  // Show preview, hide drop zone
  elUploadProgress.style.display = "none";
  elUploadPreview.style.display  = "block";
  elUploadZone.style.display     = "none";
}

/**
 * Revoke blob URL and reset all pending-media state.
 * Does NOT affect existingMedia* (those come from Firestore).
 */
function clearPendingMedia() {
  if (pendingPreviewUrl) { URL.revokeObjectURL(pendingPreviewUrl); pendingPreviewUrl = null; }
  if (activeUploadTask)  { activeUploadTask.cancel(); activeUploadTask = null; }
  pendingFile = null;
}

/**
 * Called when the user clicks "Remove" on the preview panel.
 * Also sets removeExisting=true if editing a post that had media.
 */
function removeStagedMedia() {
  clearPendingMedia();
  elUploadPreviewMedia.innerHTML = "";
  elUploadPreview.style.display  = "none";
  elUploadZone.style.display     = "flex";
  // Reset the hidden file input so the same file can be re-selected
  elFMedia.value = "";
  // Mark existing media for deletion (will execute on form save)
  if (existingMediaUrl) removeExisting = true;
}

/**
 * Uploads pendingFile to Firebase Storage under media/{uid}/{timestamp}_{random}.ext
 * Returns { url, path, mediaType } on success.
 * Shows the progress bar while uploading.
 * Throws on error or cancellation.
 */
function uploadToStorage(file) {
  return new Promise((resolve, reject) => {
    const isVideo  = ALLOWED_VIDEO_TYPES.includes(file.type);
    const ext      = file.name.split(".").pop().toLowerCase() || (isVideo ? "mp4" : "jpg");
    const uid      = currentUser.uid;
    const filename = `${Date.now()}_${Math.random().toString(36).slice(2, 9)}.${ext}`;
    const path     = `media/${uid}/${filename}`;
    const fileRef  = storageRef(storage, path);

    // Show progress bar
    elUploadProgress.style.display = "flex";
    setUploadProgress(0);

    const task = uploadBytesResumable(fileRef, file, { contentType: file.type });
    activeUploadTask = task;

    task.on(
      "state_changed",

      // Progress callback — fires repeatedly during upload
      snapshot => {
        const pct = Math.round((snapshot.bytesTransferred / snapshot.totalBytes) * 100);
        setUploadProgress(pct);
      },

      // Error callback
      err => {
        activeUploadTask = null;
        elUploadProgress.style.display = "none";
        if (err.code === "storage/canceled") {
          reject(new Error("Upload cancelled."));
        } else {
          reject(err);
        }
      },

      // Completion callback
      async () => {
        activeUploadTask = null;
        try {
          const url = await getDownloadURL(task.snapshot.ref);
          resolve({ url, path, mediaType: isVideo ? "video" : "image" });
        } catch (e) {
          reject(e);
        }
      }
    );
  });
}

/** Update progress bar DOM. */
function setUploadProgress(pct) {
  elUploadProgressFill.style.width      = pct + "%";
  elUploadProgressPct.textContent        = pct + "%";
  elUploadProgress.setAttribute("aria-valuenow", pct);
}

/** Try to delete a file from Storage by path. Non-fatal. */
async function deleteStorageFile(path) {
  if (!path) return;
  try {
    await deleteObject(storageRef(storage, path));
  } catch (e) {
    // Ignore — file may already be gone
    console.warn("Storage delete skipped:", e.code);
  }
}

/* ════════════════════════════════════════════════════════════
   ANNOUNCEMENT FORM  (create / edit)
════════════════════════════════════════════════════════════ */
function openForm(mode, ann = null) {
  formMode  = mode;
  editingId = null;
  removeExisting    = false;
  existingMediaUrl  = null;
  existingMediaPath = null;
  existingMediaType = null;

  // Reset media UI state
  clearPendingMedia();
  elUploadPreviewMedia.innerHTML = "";
  elUploadPreview.style.display  = "none";
  elUploadProgress.style.display = "none";
  elUploadZone.style.display     = "flex";
  elFMedia.value = "";

  if (mode === "edit" && ann) {
    editingId              = ann.id;
    elFTitle.value         = ann.title    || "";
    elFCategory.value      = ann.category || "general";
    elFBody.value          = ann.body     || "";
    elFExpiry.value        = ann.expiresAt?.toDate ? toDateInputValue(ann.expiresAt.toDate()) : "";
    elFAttachment.value    = ann.attachmentUrl || "";
    elFormCardTitle.textContent = "Edit Announcement";
    elBtnPostSubmit.textContent = "Save Changes";

    // If announcement has existing media, show it in the preview
    if (ann.mediaUrl) {
      existingMediaUrl  = ann.mediaUrl;
      existingMediaPath = ann.mediaStoragePath || null;
      existingMediaType = ann.mediaType || "image";

      elUploadPreviewMedia.innerHTML = "";
      if (existingMediaType === "video") {
        const vid = document.createElement("video");
        vid.src      = existingMediaUrl;
        vid.controls = true;
        vid.preload  = "metadata";
        elUploadPreviewMedia.appendChild(vid);
      } else {
        const img = document.createElement("img");
        img.src = existingMediaUrl;
        img.alt = "";
        elUploadPreviewMedia.appendChild(img);
      }

      elPreviewFileName.textContent  = "Current media";
      elPreviewFileSize.textContent  = existingMediaType === "video" ? "Video" : "Image";
      elUploadPreview.style.display  = "block";
      elUploadZone.style.display     = "none";
    }
  } else {
    elFTitle.value         = "";
    elFCategory.value      = "general";
    elFBody.value          = "";
    elFExpiry.value        = "";
    elFAttachment.value    = "";
    elFormCardTitle.textContent = "New Announcement";
    elBtnPostSubmit.textContent = "Post Announcement";
  }

  updateCharCount();
  elPostFormWrap.style.display = "block";
  elPostFormWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
  setTimeout(() => elFTitle.focus(), 180);
}

function closeForm() {
  // Cancel any in-flight upload
  if (activeUploadTask) { activeUploadTask.cancel(); activeUploadTask = null; }
  clearPendingMedia();
  elPostFormWrap.style.display = "none";
}

function toggleForm() {
  elPostFormWrap.style.display === "block" ? closeForm() : openForm("create");
}

function updateCharCount() {
  const len = elFBody.value.length;
  elCharCount.textContent = `${len} / 1200`;
  elCharCount.className   = len > 1100 ? "char-count warn" : "char-count";
}

/* ════════════════════════════════════════════════════════════
   FORM SUBMIT  (create or edit)
════════════════════════════════════════════════════════════ */
async function submitPost() {
  const title      = elFTitle.value.trim();
  const body       = elFBody.value.trim();
  const category   = elFCategory.value;
  const attachment = elFAttachment.value.trim();
  const expiryStr  = elFExpiry.value;

  // Validation
  if (!title) { showToast("A title is required."); elFTitle.focus(); return; }
  if (!body)  { showToast("Message cannot be empty."); elFBody.focus(); return; }
  if (!currentUser || (userRole !== "owner" && userRole !== "teacher")) {
    showToast("Permission denied."); return;
  }
  if (attachment && !isValidUrl(attachment)) {
    showToast("Resource URL is not valid."); elFAttachment.focus(); return;
  }

  // Lock UI
  elBtnPostSubmit.disabled    = true;
  elBtnPostSubmit.textContent = formMode === "edit" ? "Saving…" : "Posting…";

  try {
    // ── Step 1: Upload new media if a file is pending ──
    let mediaUrl         = null;
    let mediaStoragePath = null;
    let mediaType        = null;

    if (pendingFile) {
      try {
        const result = await uploadToStorage(pendingFile);
        mediaUrl         = result.url;
        mediaStoragePath = result.path;
        mediaType        = result.mediaType;
      } catch (uploadErr) {
        showToast("Upload failed: " + uploadErr.message);
        return; // Leave form open so user can retry
      }
    } else if (existingMediaUrl && !removeExisting) {
      // Editing but keeping existing media untouched
      mediaUrl         = existingMediaUrl;
      mediaStoragePath = existingMediaPath;
      mediaType        = existingMediaType;
    }

    // ── Step 2: Delete old storage file if needed ──
    // (either user removed it, or user replaced it with a new file)
    if (existingMediaPath && (removeExisting || pendingFile)) {
      await deleteStorageFile(existingMediaPath);
    }

    // ── Step 3: Write to Firestore ──
    const payload = {
      title,
      body,
      category,
      attachmentUrl:    attachment     || null,
      expiresAt:        expiryStr      ? new Date(expiryStr + "T23:59:59") : null,
      mediaUrl:         mediaUrl       || null,
      mediaStoragePath: mediaStoragePath || null,
      mediaType:        mediaType      || null,
      authorName:       currentUser.displayName || "Staff",
      authorPhoto:      currentUser.photoURL    || "",
      authorId:         currentUser.uid,
      authorEmail:      currentUser.email.toLowerCase()
    };

    if (formMode === "edit" && editingId) {
      await updateDoc(doc(db, "announcements", editingId), {
        ...payload, updatedAt: serverTimestamp()
      });
      showToast("Announcement updated.");
    } else {
      payload.pinned    = false;
      payload.createdAt = serverTimestamp();
      await addDoc(collection(db, "announcements"), payload);
      showToast("Announcement posted.");
    }

    closeForm();

  } finally {
    elBtnPostSubmit.disabled    = false;
    elBtnPostSubmit.textContent = formMode === "edit" ? "Save Changes" : "Post Announcement";
  }
}

/* ════════════════════════════════════════════════════════════
   DELETE ANNOUNCEMENT
════════════════════════════════════════════════════════════ */
async function deleteAnnouncement(id, authorId) {
  if (!currentUser) { showToast("Not signed in."); return; }
  if (currentUser.uid !== authorId && userRole !== "owner") {
    showToast("You can only delete your own announcements."); return;
  }
  if (!confirm("Delete this announcement? This cannot be undone.")) return;

  // Find announcement data before deleting (to get storage path)
  const ann = allAnnouncements.find(a => a.id === id);

  try {
    await deleteDoc(doc(db, "announcements", id));
    // Also delete media from Storage (best-effort, non-fatal)
    if (ann?.mediaStoragePath) await deleteStorageFile(ann.mediaStoragePath);
    showToast("Announcement deleted.");
  } catch (err) {
    showToast("Error deleting: " + err.message);
  }
}

/* ════════════════════════════════════════════════════════════
   PIN / UNPIN (owner only)
════════════════════════════════════════════════════════════ */
async function togglePin(id, currentlyPinned) {
  if (userRole !== "owner") { showToast("Only the owner can pin announcements."); return; }
  try {
    await updateDoc(doc(db, "announcements", id), { pinned: !currentlyPinned });
    showToast(currentlyPinned ? "Unpinned." : "Announcement pinned.");
  } catch (err) {
    showToast("Error: " + err.message);
  }
}

/* ════════════════════════════════════════════════════════════
   REAL-TIME ANNOUNCEMENTS LISTENER
════════════════════════════════════════════════════════════ */
const annQuery = query(collection(db, "announcements"), orderBy("createdAt", "desc"));

onSnapshot(annQuery, snap => {
  allAnnouncements = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  // Pinned first, then newest
  allAnnouncements.sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned));
  updateStats();
  renderFiltered();
});

/* ════════════════════════════════════════════════════════════
   FILTER & SEARCH
════════════════════════════════════════════════════════════ */
function setFilter(cat) {
  currentFilter = cat;
  $$(".filter-btn").forEach(b => b.classList.toggle("active", b.dataset.filter === cat));
  renderFiltered();
}

function handleSearch(e) {
  searchQuery = e.target.value.toLowerCase().trim();
  renderFiltered();
}

function renderFiltered() {
  let list = [...allAnnouncements];
  if (currentFilter !== "all") list = list.filter(a => a.category === currentFilter);
  if (searchQuery)             list = list.filter(a =>
    a.title.toLowerCase().includes(searchQuery) ||
    a.body.toLowerCase().includes(searchQuery)  ||
    (a.authorName || "").toLowerCase().includes(searchQuery)
  );
  renderCards(list);
}

/* ════════════════════════════════════════════════════════════
   RENDER ANNOUNCEMENT CARDS
════════════════════════════════════════════════════════════ */
function renderCards(items) {
  if (!items.length) {
    elAnnList.innerHTML        = "";
    elEmptyState.style.display = "flex";
    $("emptySub").textContent  = searchQuery
      ? `No results for "${searchQuery}".`
      : currentFilter !== "all"
        ? `No ${currentFilter} announcements.`
        : "No announcements have been posted yet.";
    return;
  }

  elEmptyState.style.display = "none";
  const isOwner = userRole === "owner";
  const canPost = isOwner || userRole === "teacher";

  elAnnList.innerHTML = items.map((ann, i) => {
    const now        = Date.now();
    const expired    = ann.expiresAt?.toDate && ann.expiresAt.toDate().getTime() < now;
    const isAuthor   = currentUser?.uid === ann.authorId;
    const dateStr    = timeAgo(ann.createdAt);

    // Badges
    const badgeHtml = [
      ann.pinned  ? `<span class="tag tag-pinned">Pinned</span>`   : "",
      expired     ? `<span class="tag tag-expired">Expired</span>` : "",
      `<span class="tag tag-${esc(ann.category)}">${capitalize(ann.category)}</span>`
    ].join("");

    // Expiry label
    const expiryHtml = ann.expiresAt?.toDate && !expired
      ? `<span class="ann-dot"></span>
         <span class="ann-expiry">Expires ${
           ann.expiresAt.toDate().toLocaleDateString("en-IE",{ day:"numeric", month:"short", year:"numeric" })
         }</span>`
      : "";

    // Media (image or video)
    let mediaHtml = "";
    if (ann.mediaUrl && ann.mediaType === "image") {
      mediaHtml = `<div class="ann-media">
        <img src="${esc(ann.mediaUrl)}" alt="" loading="lazy"/>
      </div>`;
    } else if (ann.mediaUrl && ann.mediaType === "video") {
      mediaHtml = `<div class="ann-media">
        <video src="${esc(ann.mediaUrl)}" controls preload="metadata"></video>
      </div>`;
    }

    // Resource link
    const resourceHtml = ann.attachmentUrl
      ? `<a class="ann-resource" href="${esc(ann.attachmentUrl)}" target="_blank" rel="noopener noreferrer">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
             <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
             <polyline points="15 3 21 3 21 9"/>
             <line x1="10" y1="14" x2="21" y2="3"/>
           </svg>
           Resource
         </a>`
      : "";

    // Author photo or initial
    const photoHtml = ann.authorPhoto
      ? `<img class="ann-photo" src="${esc(ann.authorPhoto)}" alt=""/>`
      : `<span class="ann-photo">${(ann.authorName || "?")[0].toUpperCase()}</span>`;

    // Action buttons
    let actionsHtml = "";
    if (canPost && (isOwner || isAuthor)) {
      const pinBtn = isOwner
        ? `<button class="ann-act ${ann.pinned ? "pinned-on" : ""}"
                   data-action="pin" data-id="${ann.id}" data-pinned="${ann.pinned}">
             ${ann.pinned ? "Unpin" : "Pin"}
           </button>`
        : "";
      const editBtn = (isAuthor || isOwner)
        ? `<button class="ann-act" data-action="edit" data-id="${ann.id}">Edit</button>`
        : "";
      const delBtn  = (isAuthor || isOwner)
        ? `<button class="ann-act danger" data-action="delete" data-id="${ann.id}" data-author="${ann.authorId}">Delete</button>`
        : "";
      actionsHtml = `<div class="ann-actions">${pinBtn}${editBtn}${delBtn}</div>`;
    }

    return `
      <div class="ann-card${ann.pinned ? " pinned" : ""}${expired ? " expired" : ""}"
           data-cat="${esc(ann.category)}"
           data-id="${ann.id}"
           style="animation-delay:${Math.min(i * 0.04, 0.4)}s"
           role="listitem">
        <div class="ann-top">
          <h2 class="ann-title">${esc(ann.title)}</h2>
          <div class="ann-badges">${badgeHtml}</div>
        </div>
        <p class="ann-body">${esc(ann.body)}</p>
        ${mediaHtml}
        <div class="ann-footer">
          <div class="ann-meta">
            ${photoHtml}
            <span class="ann-author">${esc(ann.authorName || "Staff")}</span>
            <span class="ann-dot"></span>
            <span class="ann-date">${dateStr}</span>
            ${expiryHtml}
          </div>
          ${resourceHtml}
          ${actionsHtml}
        </div>
      </div>`;
  }).join("");
}

/* ════════════════════════════════════════════════════════════
   CARD ACTION DELEGATION
════════════════════════════════════════════════════════════ */
elAnnList.addEventListener("click", e => {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const { action, id, pinned, author } = btn.dataset;
  if      (action === "delete") deleteAnnouncement(id, author);
  else if (action === "pin")    togglePin(id, pinned === "true");
  else if (action === "edit") {
    const ann = allAnnouncements.find(a => a.id === id);
    if (ann) openForm("edit", ann);
  }
});

/* ════════════════════════════════════════════════════════════
   STATS BAR
════════════════════════════════════════════════════════════ */
function updateStats() {
  $("statTotal").textContent  = allAnnouncements.length;
  $("statEvents").textContent = allAnnouncements.filter(a => a.category === "event").length;
  $("statUrgent").textContent = allAnnouncements.filter(a => a.category === "urgent").length;
  $("statPinned").textContent = allAnnouncements.filter(a => a.pinned).length;
}

/* ════════════════════════════════════════════════════════════
   ADMIN PANEL
════════════════════════════════════════════════════════════ */
function openAdminPanel() {
  elAdminModal.style.display = "flex";
  startTeachersListener();
}

function closeAdminPanel() {
  elAdminModal.style.display = "none";
  if (unsubTeachers) { unsubTeachers(); unsubTeachers = null; }
}

function startTeachersListener() {
  if (unsubTeachers) unsubTeachers();
  const q = query(collection(db, "roles"), where("role", "==", "teacher"));
  unsubTeachers = onSnapshot(q, snap => {
    renderTeachers(snap.docs.map(d => ({ id: d.id, ...d.data() })));
  });
}

function renderTeachers(list) {
  if (!list.length) {
    elTeacherList.innerHTML = `<p class="text-dim">No teachers assigned yet.</p>`;
    return;
  }
  elTeacherList.innerHTML = list.map(t => {
    const initial  = (t.displayName || t.email || "?")[0].toUpperCase();
    const photoEl  = t.photoURL
      ? `<img class="teacher-avatar" src="${esc(t.photoURL)}" alt=""/>`
      : `<div class="teacher-avatar">${initial}</div>`;
    return `
      <div class="teacher-item">
        ${photoEl}
        <div class="teacher-info">
          <div class="teacher-name">${esc(t.displayName || "Unknown")}</div>
          <div class="teacher-email">${esc(t.email || "")}</div>
        </div>
        <button class="btn-remove" data-uid="${esc(t.id)}">Remove</button>
      </div>`;
  }).join("");
}

elTeacherList.addEventListener("click", async e => {
  const btn = e.target.closest(".btn-remove");
  if (!btn) return;
  if (!confirm("Remove this teacher? They will lose posting access immediately.")) return;
  try {
    await deleteDoc(doc(db, "roles", btn.dataset.uid));
    showToast("Teacher access revoked.");
  } catch (err) {
    showToast("Error: " + err.message);
  }
});

async function addTeacher() {
  const email = elTeacherEmail.value.trim().toLowerCase();
  if (!email)               { setFeedback("Please enter an email address.", "err"); return; }
  if (!email.includes("@")) { setFeedback("Invalid email format.",          "err"); return; }

  elBtnAddTeacher.disabled    = true;
  elBtnAddTeacher.textContent = "Searching…";

  try {
    const q    = query(collection(db, "users"), where("email", "==", email));
    const snap = await getDocs(q);

    if (snap.empty) {
      setFeedback("No account found. Ask them to sign in to PyroScroll first.", "err"); return;
    }

    const userDoc  = snap.docs[0];
    const uid      = userDoc.id;
    const userData = userDoc.data();
    const roleSnap = await getDoc(doc(db, "roles", uid));

    if (roleSnap.exists()) {
      const existing = roleSnap.data().role;
      if (existing === "owner")   { setFeedback("This account is the owner.",         "err"); return; }
      if (existing === "teacher") { setFeedback("This user is already a teacher.",     "err"); return; }
    }

    await setDoc(doc(db, "roles", uid), {
      email:       userData.email,
      displayName: userData.displayName || "",
      photoURL:    userData.photoURL    || "",
      role:        "teacher",
      assignedBy:  currentUser.email,
      assignedAt:  serverTimestamp()
    });

    setFeedback(`${userData.displayName || email} has been assigned as a teacher.`, "ok");
    elTeacherEmail.value = "";
  } catch (err) {
    setFeedback("Error: " + err.message, "err");
  } finally {
    elBtnAddTeacher.disabled    = false;
    elBtnAddTeacher.textContent = "Assign";
  }
}

function setFeedback(msg, type) {
  elAddFeedback.textContent = msg;
  elAddFeedback.className   = "admin-feedback " + type;
  clearTimeout(elAddFeedback._t);
  elAddFeedback._t = setTimeout(() => { elAddFeedback.textContent = ""; }, 5000);
}

/* ════════════════════════════════════════════════════════════
   EVENT LISTENERS
════════════════════════════════════════════════════════════ */
elBtnLogin.addEventListener("click",       signInWithGoogle);
elBtnLoginPrompt.addEventListener("click", signInWithGoogle);
elBtnSignOut.addEventListener("click",     signOutUser);
elBtnAdmin.addEventListener("click",       openAdminPanel);
elBtnCloseAdmin.addEventListener("click",  closeAdminPanel);
elBtnNewPost.addEventListener("click",     toggleForm);
elBtnCancelForm.addEventListener("click",  closeForm);
elBtnPostSubmit.addEventListener("click",  submitPost);
elBtnAddTeacher.addEventListener("click",  addTeacher);
elFBody.addEventListener("input",          updateCharCount);
elSearchInput.addEventListener("input",    handleSearch);

$$(".filter-btn").forEach(btn => btn.addEventListener("click", () => setFilter(btn.dataset.filter)));

elAdminModal.addEventListener("click", e => { if (e.target === elAdminModal) closeAdminPanel(); });
elTeacherEmail.addEventListener("keydown", e => { if (e.key === "Enter") addTeacher(); });

// ── Upload zone: click triggers file input ──
elBtnBrowseMedia.addEventListener("click", e => {
  e.stopPropagation();
  elFMedia.click();
});
elUploadZone.addEventListener("click", () => elFMedia.click());
elUploadZone.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); elFMedia.click(); } });

// ── File input change ──
elFMedia.addEventListener("change", () => {
  if (elFMedia.files.length > 0) handleFileSelection(elFMedia.files[0]);
});

// ── Drag & drop ──
elUploadZone.addEventListener("dragenter", e => { e.preventDefault(); elUploadZone.classList.add("drag-over"); });
elUploadZone.addEventListener("dragover",  e => { e.preventDefault(); elUploadZone.classList.add("drag-over"); });
elUploadZone.addEventListener("dragleave", e => {
  // Only remove class if leaving the zone entirely (not entering a child)
  if (!elUploadZone.contains(e.relatedTarget)) elUploadZone.classList.remove("drag-over");
});
elUploadZone.addEventListener("drop", e => {
  e.preventDefault();
  elUploadZone.classList.remove("drag-over");
  const file = e.dataTransfer?.files?.[0];
  if (file) handleFileSelection(file);
});

// ── Remove staged media ──
elBtnRemoveMedia.addEventListener("click", removeStagedMedia);

/* ════════════════════════════════════════════════════════════
   UTILITY HELPERS
════════════════════════════════════════════════════════════ */
function showToast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 3400);
}

function timeAgo(ts) {
  if (!ts?.toDate) return "Just now";
  const diffMs = Date.now() - ts.toDate().getTime();
  const m = Math.floor(diffMs / 60_000);
  const h = Math.floor(diffMs / 3_600_000);
  const d = Math.floor(diffMs / 86_400_000);
  if (m < 1)  return "Just now";
  if (m < 60) return `${m}m ago`;
  if (h < 24) return `${h}h ago`;
  if (d < 7)  return `${d}d ago`;
  return ts.toDate().toLocaleDateString("en-IE", { day:"numeric", month:"short", year:"numeric" });
}

function toDateInputValue(date) {
  return date.toISOString().split("T")[0];
}

function firstWord(str) {
  return str ? str.split(" ")[0] : "";
}

function capitalize(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : "";
}

function isValidUrl(str) {
  try { return ["http:", "https:"].includes(new URL(str).protocol); } catch { return false; }
}

function formatBytes(bytes) {
  if (bytes < 1024)        return bytes + " B";
  if (bytes < 1_048_576)   return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1_048_576).toFixed(1) + " MB";
}

/** HTML-escape a string to prevent XSS. */
function esc(str = "") {
  return String(str)
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;")
    .replace(/'/g,  "&#039;");
}
