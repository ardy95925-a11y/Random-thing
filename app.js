/**
 * PyroScroll — app.js
 * Firebase-backed school announcement board
 *
 * Roles stored in Firestore `roles/{uid}`:
 *   owner   → Oleksandr.lahoza.24@phcol.ie (hardcoded + enforced)
 *   teacher → assigned by owner; can post/edit own announcements
 *   (none)  → viewer; read-only access
 *
 * IMPORTANT — Set these Firestore security rules before deploying:
 * ──────────────────────────────────────────────────────────────
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
 * ──────────────────────────────────────────────────────────────
 */

import { initializeApp }     from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getAnalytics }      from "https://www.gstatic.com/firebasejs/10.12.2/firebase-analytics.js";
import {
  getAuth, GoogleAuthProvider,
  signInWithPopup, signOut as fbSignOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore, collection, doc,
  addDoc, setDoc, getDoc, getDocs, deleteDoc, updateDoc,
  query, orderBy, where, onSnapshot, serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";

/* ════════════════════════════════════════════════════════════
   CONFIG & CONSTANTS
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

/** The one and only owner — enforced both client-side and via security rules. */
const OWNER_EMAIL = "oleksandr.lahoza.24@phcol.ie";

/* ════════════════════════════════════════════════════════════
   FIREBASE INIT
════════════════════════════════════════════════════════════ */
const fbApp    = initializeApp(FIREBASE_CONFIG);
getAnalytics(fbApp);                           // optional analytics
const auth     = getAuth(fbApp);
const db       = getFirestore(fbApp);
const provider = new GoogleAuthProvider();
provider.setCustomParameters({ hd: "phcol.ie" }); // hint: restrict to school domain

/* ════════════════════════════════════════════════════════════
   APP STATE
════════════════════════════════════════════════════════════ */
let currentUser       = null;
let userRole          = null;   // 'owner' | 'teacher' | null
let allAnnouncements  = [];
let currentFilter     = "all";
let searchQuery       = "";
let formMode          = "create";  // 'create' | 'edit'
let editingId         = null;
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

  // Tear down old role listener
  if (unsubRoleListener) { unsubRoleListener(); unsubRoleListener = null; }

  if (user) {
    // ── Register user record so owner can search by email ──
    try {
      await setDoc(doc(db, "users", user.uid), {
        uid:         user.uid,
        email:       user.email.toLowerCase(),
        displayName: user.displayName  || "",
        photoURL:    user.photoURL     || "",
        lastSeen:    serverTimestamp()
      }, { merge: true });
    } catch { /* non-critical */ }

    // ── Ensure owner role is stamped into Firestore ──
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

    // ── Live role listener (reacts immediately if owner changes role) ──
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

  // Header auth controls
  if (loggedIn) {
    elUserChip.style.display     = "inline-flex";
    elUserAvatar.src             = currentUser.photoURL || "";
    elUserAvatar.style.display   = currentUser.photoURL ? "" : "none";
    elUserName.textContent       = firstWord(currentUser.displayName) || "User";
    const roleLbl                = isOwner ? "Owner" : userRole === "teacher" ? "Teacher" : "";
    elUserRoleBadge.textContent  = roleLbl;
    elUserRoleBadge.className    = "role-badge " + (isOwner ? "role-owner" : userRole === "teacher" ? "role-teacher" : "");
    elBtnSignOut.style.display   = "block";
    elBtnLogin.style.display     = "none";
  } else {
    elUserChip.style.display     = "none";
    elBtnSignOut.style.display   = "none";
    elBtnLogin.style.display     = "inline-flex";
  }

  // Login prompt (only when signed out)
  elLoginPrompt.style.display   = loggedIn ? "none" : "flex";
  // New-post button (teacher or owner)
  elBtnNewPost.style.display    = canPost  ? "inline-flex" : "none";
  // Admin button (owner only)
  elBtnAdmin.style.display      = isOwner  ? "inline-flex" : "none";

  // Page subtitle
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
   ANNOUNCEMENT FORM  (create / edit)
════════════════════════════════════════════════════════════ */
function openForm(mode, ann = null) {
  formMode  = mode;
  editingId = null;

  if (mode === "edit" && ann) {
    editingId                   = ann.id;
    elFTitle.value              = ann.title    || "";
    elFCategory.value           = ann.category || "general";
    elFBody.value               = ann.body     || "";
    elFExpiry.value             = ann.expiresAt?.toDate
      ? toDateInputValue(ann.expiresAt.toDate()) : "";
    elFAttachment.value         = ann.attachmentUrl || "";
    elFormCardTitle.textContent = "Edit Announcement";
    elBtnPostSubmit.textContent = "Save Changes";
  } else {
    elFTitle.value              = "";
    elFCategory.value           = "general";
    elFBody.value               = "";
    elFExpiry.value             = "";
    elFAttachment.value         = "";
    elFormCardTitle.textContent = "New Announcement";
    elBtnPostSubmit.textContent = "Post Announcement";
  }

  updateCharCount();
  elPostFormWrap.style.display = "block";
  elPostFormWrap.scrollIntoView({ behavior: "smooth", block: "nearest" });
  setTimeout(() => elFTitle.focus(), 180);
}

function closeForm() {
  elPostFormWrap.style.display = "none";
}

function toggleForm() {
  if (elPostFormWrap.style.display === "block") {
    closeForm();
  } else {
    openForm("create");
  }
}

function updateCharCount() {
  const len = elFBody.value.length;
  elCharCount.textContent = `${len} / 1200`;
  elCharCount.className   = len > 1100 ? "char-count warn" : "char-count";
}

async function submitPost() {
  const title      = elFTitle.value.trim();
  const body       = elFBody.value.trim();
  const category   = elFCategory.value;
  const attachment = elFAttachment.value.trim();
  const expiryStr  = elFExpiry.value;

  // Client-side guards
  if (!title)  { showToast("A title is required."); elFTitle.focus();  return; }
  if (!body)   { showToast("Message cannot be empty."); elFBody.focus(); return; }
  if (!currentUser || (userRole !== "owner" && userRole !== "teacher")) {
    showToast("Permission denied."); return;
  }

  // Validate URL if provided
  if (attachment && !isValidUrl(attachment)) {
    showToast("Resource URL is not valid."); elFAttachment.focus(); return;
  }

  const payload = {
    title,
    body,
    category,
    attachmentUrl: attachment || null,
    expiresAt:     expiryStr ? new Date(expiryStr + "T23:59:59") : null,
    authorName:    currentUser.displayName || "Staff",
    authorPhoto:   currentUser.photoURL    || "",
    authorId:      currentUser.uid,
    authorEmail:   currentUser.email.toLowerCase()
  };

  elBtnPostSubmit.disabled    = true;
  elBtnPostSubmit.textContent = formMode === "edit" ? "Saving…" : "Posting…";

  try {
    if (formMode === "edit" && editingId) {
      // Strip immutable fields from edit payload
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
  } catch (err) {
    showToast("Error: " + err.message);
  } finally {
    elBtnPostSubmit.disabled    = false;
    elBtnPostSubmit.textContent = formMode === "edit" ? "Save Changes" : "Post Announcement";
  }
}

/* ════════════════════════════════════════════════════════════
   DELETE
════════════════════════════════════════════════════════════ */
async function deleteAnnouncement(id, authorId) {
  if (!currentUser) { showToast("Not signed in."); return; }
  if (currentUser.uid !== authorId && userRole !== "owner") {
    showToast("You can only delete your own announcements."); return;
  }
  if (!confirm("Delete this announcement? This cannot be undone.")) return;
  try {
    await deleteDoc(doc(db, "announcements", id));
    showToast("Announcement deleted.");
  } catch (err) {
    showToast("Error deleting: " + err.message);
  }
}

/* ════════════════════════════════════════════════════════════
   PIN / UNPIN  (owner only)
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
// Order by createdAt; sort pinned first in JS (avoids needing a composite index)
const annQuery = query(collection(db, "announcements"), orderBy("createdAt", "desc"));

onSnapshot(annQuery, snap => {
  allAnnouncements = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  // Stable sort: pinned first, then by original Firestore order (createdAt desc)
  allAnnouncements.sort((a, b) => Number(!!b.pinned) - Number(!!a.pinned));
  updateStats();
  renderFiltered();
});

/* ════════════════════════════════════════════════════════════
   FILTER & SEARCH
════════════════════════════════════════════════════════════ */
function setFilter(cat, btn) {
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
  const canPost  = userRole === "owner" || userRole === "teacher";
  const isOwner  = userRole === "owner";

  elAnnList.innerHTML = items.map((ann, i) => {
    const now        = Date.now();
    const expired    = ann.expiresAt?.toDate && ann.expiresAt.toDate().getTime() < now;
    const isAuthor   = currentUser?.uid === ann.authorId;
    const canEdit    = isAuthor || isOwner;
    const canDelete  = isAuthor || isOwner;
    const dateStr    = timeAgo(ann.createdAt);

    // Build badge row
    const badgeHtml = [
      ann.pinned  ? `<span class="tag tag-pinned">Pinned</span>`   : "",
      expired     ? `<span class="tag tag-expired">Expired</span>` : "",
      `<span class="tag tag-${esc(ann.category)}">${capitalize(ann.category)}</span>`
    ].join("");

    // Expiry line
    const expiryHtml = ann.expiresAt?.toDate && !expired
      ? `<span class="ann-dot"></span><span class="ann-expiry">Expires ${
          ann.expiresAt.toDate().toLocaleDateString("en-IE", { day:"numeric", month:"short", year:"numeric" })
        }</span>`
      : "";

    // Resource link
    const resourceHtml = ann.attachmentUrl
      ? `<a class="ann-resource" href="${esc(ann.attachmentUrl)}" target="_blank" rel="noopener noreferrer">
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
             <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
             <polyline points="15 3 21 3 21 9"/>
             <line x1="10" y1="14" x2="21" y2="3"/>
           </svg>
           View Resource
         </a>`
      : "";

    // Author photo / initials
    const photoHtml = ann.authorPhoto
      ? `<img class="ann-photo" src="${esc(ann.authorPhoto)}" alt="" />`
      : `<span class="ann-photo">${(ann.authorName || "?")[0].toUpperCase()}</span>`;

    // Action buttons (only for those with rights)
    let actionsHtml = "";
    if (canPost && (isOwner || isAuthor)) {
      const pinBtn = isOwner
        ? `<button class="ann-act ${ann.pinned ? "pinned-on" : ""}" data-action="pin" data-id="${ann.id}" data-pinned="${ann.pinned}">
             ${ann.pinned ? "Unpin" : "Pin"}
           </button>`
        : "";
      const editBtn = canEdit
        ? `<button class="ann-act" data-action="edit" data-id="${ann.id}">Edit</button>`
        : "";
      const delBtn = canDelete
        ? `<button class="ann-act danger" data-action="delete" data-id="${ann.id}" data-author="${ann.authorId}">Delete</button>`
        : "";
      actionsHtml = `<div class="ann-actions">${pinBtn}${editBtn}${delBtn}</div>`;
    }

    return `
      <div class="ann-card ${ann.pinned ? "pinned" : ""} ${expired ? "expired" : ""}"
           data-cat="${esc(ann.category)}" data-id="${ann.id}"
           style="animation-delay: ${Math.min(i * 0.04, 0.4)}s"
           role="listitem">
        <div class="ann-top">
          <h2 class="ann-title">${esc(ann.title)}</h2>
          <div class="ann-badges">${badgeHtml}</div>
        </div>
        <p class="ann-body">${esc(ann.body)}</p>
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
   EVENT DELEGATION — announcement card buttons
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
   ADMIN PANEL (owner only)
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
  if (unsubTeachers) { unsubTeachers(); }
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
    const initial = (t.displayName || t.email || "?")[0].toUpperCase();
    const photo   = t.photoURL
      ? `<img class="teacher-avatar" src="${esc(t.photoURL)}" alt=""/>`
      : `<div class="teacher-avatar">${initial}</div>`;
    return `
      <div class="teacher-item">
        ${photo}
        <div class="teacher-info">
          <div class="teacher-name">${esc(t.displayName || "Unknown")}</div>
          <div class="teacher-email">${esc(t.email || "")}</div>
        </div>
        <button class="btn-remove" data-uid="${esc(t.id)}">Remove</button>
      </div>`;
  }).join("");
}

// Remove teacher via delegation
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

// Assign teacher by email
async function addTeacher() {
  const email = elTeacherEmail.value.trim().toLowerCase();

  if (!email)              { setFeedback("Please enter an email address.", "err"); return; }
  if (!email.includes("@")) { setFeedback("Invalid email format.",         "err"); return; }

  elBtnAddTeacher.disabled    = true;
  elBtnAddTeacher.textContent = "Searching…";

  try {
    const q    = query(collection(db, "users"), where("email", "==", email));
    const snap = await getDocs(q);

    if (snap.empty) {
      setFeedback("No account found for that email. Ask them to sign in first.", "err");
      return;
    }

    const userDoc  = snap.docs[0];
    const uid      = userDoc.id;
    const userData = userDoc.data();

    // Check existing role
    const roleSnap = await getDoc(doc(db, "roles", uid));
    if (roleSnap.exists()) {
      const existingRole = roleSnap.data().role;
      if (existingRole === "owner")   { setFeedback("This account is the owner.",          "err"); return; }
      if (existingRole === "teacher") { setFeedback("This user is already a teacher.",      "err"); return; }
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
   STATIC EVENT LISTENERS
════════════════════════════════════════════════════════════ */
elBtnLogin.addEventListener("click",        signInWithGoogle);
elBtnLoginPrompt.addEventListener("click",  signInWithGoogle);
elBtnSignOut.addEventListener("click",      signOutUser);
elBtnAdmin.addEventListener("click",        openAdminPanel);
elBtnCloseAdmin.addEventListener("click",   closeAdminPanel);
elBtnNewPost.addEventListener("click",      toggleForm);
elBtnCancelForm.addEventListener("click",   closeForm);
elBtnPostSubmit.addEventListener("click",   submitPost);
elBtnAddTeacher.addEventListener("click",   addTeacher);
elFBody.addEventListener("input",           updateCharCount);
elSearchInput.addEventListener("input",     handleSearch);

// Filter buttons
$$(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => setFilter(btn.dataset.filter, btn));
});

// Close modal on backdrop click
elAdminModal.addEventListener("click", e => {
  if (e.target === elAdminModal) closeAdminPanel();
});

// Allow Enter key in teacher email field
elTeacherEmail.addEventListener("keydown", e => {
  if (e.key === "Enter") addTeacher();
});

/* ════════════════════════════════════════════════════════════
   UTILITY HELPERS
════════════════════════════════════════════════════════════ */
/** Show a brief toast notification. */
function showToast(msg) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 3400);
}

/** Human-readable relative time. */
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

/** YYYY-MM-DD string suitable for <input type="date">. */
function toDateInputValue(date) {
  return date.toISOString().split("T")[0];
}

/** Return first word of a space-separated string. */
function firstWord(str) {
  return str ? str.split(" ")[0] : "";
}

/** Capitalise first letter. */
function capitalize(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : "";
}

/** Simple URL validation. */
function isValidUrl(str) {
  try { return ["http:", "https:"].includes(new URL(str).protocol); } catch { return false; }
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
