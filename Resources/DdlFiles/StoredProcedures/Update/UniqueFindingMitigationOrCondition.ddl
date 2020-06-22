UPDATE UniqueFindings
SET
	MitigationOrCondition_ID = @MitigationOrCondition_ID
WHERE
	UniqueFinding_ID = @UniqueFinding_ID;