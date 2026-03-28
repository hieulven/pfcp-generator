# Quick Start Guide: Using Claude Code CLI for PFCP Generator

## Prerequisites

1. **Install Claude Code CLI**
   - Follow installation instructions for your system
   - Ensure you have Node.js >= 18 installed


## Phase 1: Generate Design Documents

### Step 1: Start Claude Code Session

```bash
claude-code
```

### Step 2: Provide the Main Prompt

Copy and paste the entire content of `pfcp-generator-prompt.md` into Claude Code CLI, or reference it:

```
Please read the file pfcp-generator-prompt.md and begin Phase 1: Generate the three design documents as specified.
```

### Step 3: Review Generated Documents

Claude Code will create:
- `docs/requirements.md`
- `docs/architecture.md`
- `docs/implementation.md`

Review each document carefully.

## Phase 2: Document Review and Refinement

### Step 4: Provide Feedback

If you need changes, provide specific feedback:

```
In docs/requirements.md:
- Add requirement for supporting multiple PCAP files
- Change the minimum session count to 500 instead of 100

In docs/architecture.md:
- Add a diagram for the session state machine
- Clarify the retry logic for failed messages

In docs/implementation.md:
- Add more detail on IPv6 support
- Specify the exact format for statistics output
```

### Step 5: Iterate Until Approved

Continue providing feedback until all three documents meet your requirements.

### Step 6: Final Approval

Once satisfied, explicitly approve:

```
The documents are approved. Please proceed to Phase 3: Implementation.
```

## Phase 3: Implementation

### Step 7: Begin Module Implementation

Claude Code will implement modules in the specified order. You can:

**Option A: Let it proceed autonomously**
```
Implement all modules as specified in the approved documents.
```

**Option B: Control the pace**
```
Implement the configuration module first (internal/config). 
Stop after completing unit tests so I can review.
```

### Step 8: Review Code as Modules Complete

For each module, review:
- Code quality and structure
- Test coverage
- Adherence to design documents

Provide feedback:
```
In internal/config/config.go:
- Add validation for CIDR notation
- Use viper for configuration loading

In internal/session/seid_allocator.go:
- The mutex lock should be held longer to prevent race conditions
- Add boundary check for SEID overflow
```

### Step 9: Integration

Once all modules are complete:

```
Now integrate all modules and create the main CLI entry point.
```

## Phase 4: Testing with PCAP

### Step 10: Find or Create Test PCAP

**Option A: Use existing PCAP**
```
I have a PFCP pcap file at /path/to/capture.pcap
Please test the tool with this file.
```

**Option B: Request help finding one**
```
Can you help me find a sample PFCP pcap file for testing?
Or generate a simple test scenario using your mock UPF?
```

### Step 11: Run Tests

```
# Unit tests
Run all unit tests and report results.

# Integration test with mock UPF
Set up the mock UPF and run an integration test.

# Real PCAP test
Run the tool against my PCAP file with these settings:
- SMF IP: 192.168.1.10
- UPF IP: 192.168.1.20  
- UE Pool: 10.60.0.0/24
- Dry run first (parse only)
```

### Step 12: Analyze Results

```
Show me:
1. Parsing statistics from the PCAP
2. Any errors encountered
3. Session establishment success rate
4. Performance metrics
```

## Example Complete Workflow

Here's a complete example session:

```bash
# Terminal 1: Start Claude Code
claude-code

# In Claude Code CLI:
> Please read pfcp-generator-prompt.md and pfcp-technical-reference.md
> Begin Phase 1: Generate all three design documents in the docs/ directory

[Claude generates documents]

> I've reviewed the documents. Make these changes:
> 1. In requirements.md, add support for filtering specific message types
> 2. In architecture.md, add component diagram
> 3. In implementation.md, add more details on error handling

[Claude updates documents]

> Documents approved. Proceed to Phase 3: Implementation
> Start with the configuration and session management modules

[Claude implements and tests modules]

> The configuration module looks good. Continue with the PCAP parser

[Continue until all modules complete]

> Now let's test. I have a PCAP at ./test/sample.pcap
> First, run in dry-run mode to validate parsing

> Now run with these settings:
> SMF: 10.0.0.1
> UPF: 10.0.0.2
> UE Pool: 172.16.0.0/16
> SEID start: 1000

[Review results]

> Great! Now add support for statistics export to JSON file
```

## Tips for Effective Collaboration

### 1. Be Specific in Feedback
❌ Bad: "The code doesn't look right"
✅ Good: "In modifier.go line 45, the UE IP replacement should check the V4 flag before modifying IPv4 address"

### 2. Reference the Design Documents
```
According to docs/implementation.md section 3.3, we should NOT modify F-TEID.
Please update the modifier to skip F-TEID IEs.
```

### 3. Request Incremental Changes
```
Before implementing the full network layer, can you show me:
1. The interface design
2. A simple test case
3. The error handling strategy
```

### 4. Ask for Explanations
```
Can you explain the rationale for using a separate transaction tracker
instead of embedding transaction state in the message sender?
```

### 5. Request Documentation
```
Add inline comments explaining the SEID allocation strategy
and why we chose this approach over alternatives.
```

## Common Issues and Solutions

### Issue: Generated code doesn't compile
```
There are compilation errors in internal/pfcp/decoder.go:
[paste error message]

Please fix these errors.
```

### Issue: Tests are failing
```
Unit test TestSEIDAllocator_Sequential is failing:
[paste test output]

Debug and fix the issue.
```

### Issue: Need to modify requirements mid-implementation
```
I need to add a new requirement: support for rate limiting.
Should we update the design documents first, or proceed with implementation?
```

### Issue: Performance concerns
```
The tool is too slow when processing large PCAP files.
Can you profile the code and identify bottlenecks?
```

## Monitoring Progress

Track completion using this checklist:

```
Phase 1: Design Documents
[ ] requirements.md generated
[ ] architecture.md generated  
[ ] implementation.md generated
[ ] All documents reviewed and approved

Phase 2: Implementation
[ ] internal/config module
[ ] internal/session module (SEID, IP pool)
[ ] internal/pfcp module (decoder, encoder, modifier)
[ ] internal/pcap module
[ ] internal/network module
[ ] internal/stats module
[ ] cmd/pfcp-generator CLI
[ ] Unit tests for all modules
[ ] Integration tests

Phase 3: Testing
[ ] Sample PCAP acquired/created
[ ] Parsing test passed
[ ] Mock UPF test passed
[ ] Real UPF test passed (if available)
[ ] Performance test passed
[ ] Edge cases handled

Phase 4: Documentation
[ ] README.md complete
[ ] Usage examples added
[ ] Configuration guide written
[ ] Troubleshooting section added
```

## Getting Help from Claude Code

### Ask for Clarifications
```
I don't understand the session state machine in architecture.md.
Can you explain it with a sequence diagram?
```

### Request Alternatives
```
The current SEID allocation uses sequential IDs.
What are the pros and cons of using random vs sequential?
Show me both implementations.
```

### Debugging Assistance
```
The tool crashes when parsing this specific PCAP file.
Here's the error: [paste error]
Can you help debug this?
```

## Finalizing the Project

Once testing is complete:

```
1. Generate final README with:
   - Installation instructions
   - Usage examples
   - Configuration reference
   - Troubleshooting guide

2. Create a release checklist

3. Document any known limitations or future enhancements

4. Provide instructions for contributing (if making it open source)
```

## Example: Handling Document Modifications

```
User: "In docs/implementation.md section 3.3, you specify that we modify 
      F-SEID. But the technical reference says F-TEID is allocated by UPF.
      I think there's confusion between F-SEID and F-TEID. Please clarify."

Claude Code: "You're absolutely right. Let me clarify:
             - F-SEID (Fully Qualified SEID): Contains the SEID + IP. 
               This MUST be modified.
             - F-TEID (Fully Qualified TEID): Contains the TEID + IP.
               This is allocated by UPF and must NOT be modified.
             
             I'll update docs/implementation.md section 3.3 to clearly
             distinguish between these two IEs..."

[Claude updates the document]

User: "Perfect. Now that's clear. Please continue with implementation."
```

## Next Steps After Completion

```
1. Run final integration tests
2. Generate performance benchmarks
3. Create Docker container (optional)
4. Set up CI/CD pipeline (optional)
5. Prepare for production deployment
```

## Support

If you encounter issues:
1. Review the technical reference document
2. Check the 3GPP TS 29.244 specification
3. Consult the wmnsk/go-pfcp library documentation
4. Ask Claude Code for clarification or debugging help
