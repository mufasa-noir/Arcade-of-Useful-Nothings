---
name: cv-builder
description: Builds CVs and resumes as PDFs, shaped to the target role by researching layouts and conventions that are proven to work with recruiters and ATS (applicant tracking) software. Use this skill whenever the user asks to create, build, write, draft, make, redo, tailor, or update a CV or resume, even if they only say "I need a CV for a job", paste their work history and ask for something they can send out, or mention applying for a specific position. Also use it when the user supplies a template or an example CV to follow. Output is a PDF unless the user asks for another format.
---

# CV Builder

Produce a CV that does its job: get past ATS parsing, survive a recruiter's 10-second skim, and then hold up under a careful read. The user's own specifications come first. Research on what works for their specific role comes second, and design polish comes last, in service of the other two.

The workflow has five stages. Do them in order, because each one feeds the next, and stop for the user at the two points marked **[PAUSE]**.

## 1. Capture the brief

Collect what the user has already told you, and read any files they attached (existing CV, LinkedIn export, notes, a template). Pin down:

- **Target:** the role or field, seniority level, and the market or country they're applying in (conventions differ: some markets expect a photo, date of birth, or a longer format, while others treat those as red flags).
- **Content:** work history, education, projects, skills, certifications, publications, anything else they want included.
- **Specs:** length, section order, tone, colours, fonts, language, anything they stated explicitly. Treat these as requirements, not suggestions.
- **Format:** PDF by default. Switch only if they ask for something else (for Word output, read `/mnt/skills/public/docx/SKILL.md` first).

## 2. Check for gaps **[PAUSE if anything essential is missing]**

A CV built on guesses is worse than no CV, because the user may send it out without noticing the invented parts. Before researching or building, check for missing essentials: contact details, dates for each role, job titles, employers, education details, and enough substance in each role to write real bullets.

If something essential is missing, ask for it in one compact message and wait. Group the questions so the user answers once. Where achievements are vague ("worked on backend stuff"), ask for specifics: what they built, how big, what changed because of it. Numbers are the strongest content on a CV, but only the user can supply true ones.

Never invent employers, dates, metrics, or credentials. Tightening and rephrasing the user's own facts is the job; adding facts is not.

## 3. Research what works for this role

Use `web_search` (and `web_fetch` on promising results) to find out what is known to work for this exact career and level. Search for the specific role, not "CV tips" in general, and include the current year so results aren't stale. Examples: "software engineer resume format 2026 ATS recruiters", "nursing resume example new graduate", "embedded systems engineer resume what hiring managers look for".

Look for evidence of what works, preferring these sources:
- Recruiter and hiring-manager guidance, university career centres, and professional bodies for the field
- ATS vendor or HR-tech documentation on how parsing works
- Resume examples that are reported to have led to interviews or offers

Pull out the things that transfer: section order, ideal length, how experience is described, which keywords and skills the field expects, and what to leave out. Note where two sources disagree rather than hiding it.

Why recreate and not copy: the sandbox cannot download arbitrary template files, and many online templates are someone's copyrighted design. Take the structural conventions and principles, then rebuild the layout yourself.

If the user supplied a template or example, it is the top priority. Match its structure and look as closely as you can, and use the research to fill in what the template doesn't decide (wording, ordering within sections, keywords). If it conflicts with ATS-safety, follow the template but mention the specific risk once.

## 4. Propose layouts **[PAUSE for the user's pick]**

Offer 2 or 3 distinct layout options and let the user choose before you build. Keep it short so it's easy to decide. For each option give:

- A name and a one-line description of the layout (column structure, section order, header style)
- Why it suits this role, tied to what you found in research (cite the source briefly)
- One honest tradeoff (for example "two columns look sharper but some older ATS read them out of order")

Make the options meaningfully different, not three variations on the same page. Flag which one you'd pick and why. If the user's specs or template already settle the layout, skip the menu and say so in one line, then go straight to building.

## 5. Build, verify, deliver

### Building

Default to PDF via `reportlab` (platypus for flowing text) unless the user prefers another tool. Read `/mnt/skills/public/pdf/SKILL.md` for the PDF toolkit details. Build a single script so revisions are quick.

Design principles, in priority order:
1. **Readable by machines.** Real selectable text (never text baked into images), standard section headings ("Experience", "Education", "Skills"), contact details in the page body rather than a header or footer, consistent date formats, standard embedded fonts, simple bullets. Avoid tables or text boxes for core content, since parsers often scramble them.
2. **Scannable by humans.** Clear hierarchy, generous but not wasteful whitespace, strong alignment, most relevant experience first, bullets that open with a verb and end with a result.
3. **Tasteful, not loud.** The user's design wishes lead. Where they've said nothing, use one accent colour at most, one or two typefaces, and subtle structure such as rules or small caps for headings. Visual personality should never cost legibility, parsing, or page space the content needs. Icons, skill bars, rating dots, and photos are usually net negatives for ATS and recruiters unless the user or the market specifically wants them.

Length: one page for early-career, two for most experienced candidates, longer only for academic or clinical CVs where the field expects it. If the content spills slightly over, tighten wording before shrinking fonts below about 9.5pt.

Content: write bullets from the user's facts, lead with impact, mirror keywords the research (and the target job posting, if they gave one) shows the field expects, and keep tense consistent.

### Verifying

Check the result before presenting it, because layout bugs are easy to miss:
1. Run `pdftotext -layout cv.pdf -` and confirm the text comes out in the right reading order with no garbling. This is a rough stand-in for what an ATS sees.
2. Rasterize with `pdftoppm -png -r 80 cv.pdf page` and look at each page for overflow, orphaned headings, awkward page breaks, and misalignment.
3. Confirm the page count matches the length target.

Fix problems and re-check before delivering.

### Delivering

Save to `/mnt/user-data/outputs/` with a clear filename (for example `Firstname_Lastname_CV.pdf`) and present it with `present_files`. Add a short note covering which layout was used and why, and anything the user should double-check (for example, details you could not verify). Offer one round of tweaks: they know what feels right better than any research does.
